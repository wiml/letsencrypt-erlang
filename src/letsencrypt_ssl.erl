%% Copyright 2015-2016 Guillaume Bour
%% 
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%% 
%% http://www.apache.org/licenses/LICENSE-2.0
%% 
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.

-module(letsencrypt_ssl).
-author("Guillaume Bour <guillaume@bour.cc>").
-author("Wim Lewis <wiml@hhhh.org>").

-export([private_key/2, cert_request/3, cert_autosigned/3, certificate/4]).
-export([certificate_request/2, self_signed_certificate/2]).

-include_lib("public_key/include/public_key.hrl").
-import(letsencrypt_utils, [bin/1]).

% create key
-spec private_key(undefined|{new, string()}|string(), string()) -> letsencrypt:ssl_privatekey().
private_key(undefined, CertsPath) ->
    private_key({new, "letsencrypt.key"}, CertsPath);

private_key({new, KeyFile}, CertsPath) ->
    FileName = CertsPath++"/"++KeyFile,
    Cmd = "openssl genrsa -out '"++FileName++"' 2048",
    _R = os:cmd(Cmd),

    read_private_key(FileName);
private_key(KeyFile, _) ->
    read_private_key(KeyFile).

read_private_key(Path) ->
    {ok, Pem} = file:read_file(Path),
    [Key]     = public_key:pem_decode(Pem),
    #{
        key => public_key:pem_entry_decode(Key),
        file => Path
    }.

% compatibility shims, for now.
-spec cert_request(string(), string(), list(string())) -> letsencrypt:ssl_csr().
cert_request(Domain, CertsPath, SANs) ->
    KeyFile = CertsPath ++ "/" ++ Domain ++ ".key",
    Key = read_private_key(KeyFile),
    Csr = certificate_request([Domain | SANs], maps:get(key, Key)),
    letsencrypt_utils:b64encode(Csr).


% create temporary (1 day) certificate with subjectAlternativeName
% used for tls-sni-01 challenge
-spec cert_autosigned(string(), string(), list(string())) -> {ok, string()}.
cert_autosigned(Domain, KeyFile, SANs) ->
    CertFile = "/tmp/"++Domain++"-tlssni-autosigned.pem",
    Key = read_private_key(KeyFile),
    Cert = self_signed_certificate([Domain|SANs], maps:get(key, Key)),
    file:write_file(CertFile, pem_format(Cert)),
    {ok, CertFile}.

% Generate a CSR from a list of subject names and a subject key.
-spec certificate_request(list(letsencrypt:general_name()), public_key:private_key()) -> binary().
certificate_request(SubjectNames, Key) ->
    {SubjectName, SANExtension} = cn_and_ext(SubjectNames),
    Tbs = #'CertificationRequestInfo'{
	     version=v1,
	     subject=SubjectName,
	     subjectPKInfo = subject_public_key_info(open,Key),
	     attributes = [
			   #'AttributePKCS-10'{
			      type=?'pkcs-9-at-extensionRequest',
			      values=[ opentype('Extensions', [SANExtension]) ]
			     }
			  ]
	    },
    TbsBinary = public_key:der_encode('CertificationRequestInfo', Tbs),
    SigningAlg = pkix_signature_algorithm(open, Key),
    Signature = pkix_signature(TbsBinary, SigningAlg, Key),
    public_key:der_encode('CertificationRequest', #'CertificationRequest'{
		certificationRequestInfo = Tbs,
                signatureAlgorithm = SigningAlg,
		signature = Signature}).

% Generate a short-lived, self-signed certificate for use with
% the tls-sni-01 challenge
-spec self_signed_certificate(list(letsencrypt:general_name()), public_key:private_key()) -> binary().
self_signed_certificate(SubjectNames, Key) ->
    {SubjectName, SANExtension} = cn_and_ext(SubjectNames),
    EKUExtension = #'Extension'{
		      extnID=?'id-ce-extKeyUsage',
		      critical=false,
		      % This just has the id-kp-serverAuth key usage purpose:
		      extnValue= <<48,10,6,8,43,6,1,5,5,7,3,1>>
		     },
    SigAlg = pkix_signature_algorithm(closed, Key),
    Tbs = #'TBSCertificate'{
	     version=v3,
	     serialNumber=1,
	     subject=SubjectName,
	     issuer=SubjectName,
	     validity=validity_around_now(4),
	     subjectPublicKeyInfo = subject_public_key_info(closed, Key),
	     extensions = [ SANExtension, EKUExtension ],
	     signature=SigAlg
	    },
    TbsBinary = public_key:der_encode('TBSCertificate', Tbs),
    public_key:der_encode('Certificate', #'Certificate'{
		tbsCertificate = Tbs,
                signatureAlgorithm = SigAlg,
		signature = pkix_signature(TbsBinary, SigAlg, Key)
    }).

% Returns the public key info for a given private key.
-spec subject_public_key_info(open|closed, public_key:private_key()) -> #'SubjectPublicKeyInfo'{}.
subject_public_key_info(Kind, #'RSAPrivateKey'{modulus=N,publicExponent=E}) ->
    SubjectKey = public_key:der_encode('RSAPublicKey', #'RSAPublicKey'{modulus=N, publicExponent=E}),
    #'SubjectPublicKeyInfo'{
       algorithm=#'AlgorithmIdentifier'{
		    algorithm=?'rsaEncryption',
		    parameters=maybe_opentype(Kind,<<5,0>>)
		   },
       subjectPublicKey=SubjectKey
    }.

% Returns the AlgorithmIdentifier structure for the algorithm we'll use
% when signing things with this key.
-spec pkix_signature_algorithm(open|closed, public_key:private_key()) -> #'AlgorithmIdentifier'{}.
pkix_signature_algorithm(Kind, #'RSAPrivateKey'{}) ->
    #'AlgorithmIdentifier'{
       algorithm=?'sha256WithRSAEncryption',
       parameters=maybe_opentype(Kind, <<5,0>>)
    }.

maybe_opentype(open, V) -> { asn1_OPENTYPE, V };
maybe_opentype(closed, V) -> V.

opentype(T,V) ->
    { asn1_OPENTYPE, public_key:der_encode(T, V) }.

% Given an AlgorithmIdentifier and a key, produce a signature for an input.
-spec pkix_signature(binary(), #'AlgorithmIdentifier'{}, public_key:private_key()) -> binary().
pkix_signature(Tbs, {_, ?'sha256WithRSAEncryption', _}, #'RSAPrivateKey'{modulus=N,publicExponent=E,privateExponent=D}) ->
    crypto:sign(rsa, sha256, iolist_to_binary(Tbs), [E,N,D]).

% Helper for normalizing a cert's subject name list and choosing one
% to put in the SN.
-spec acc_generalnames(letsencrypt:subject_name(), {term(), list(public_key:general_name())}) -> {term(), list(public_key:general_name())}.
acc_generalnames( {dNSName, DnsName} = Gn, { _, GNs } ) ->
    { DnsName, [Gn|GNs] };
acc_generalnames(DnsName, A) when is_list(DnsName) ->
    acc_generalnames( {dNSName, DnsName}, A );
acc_generalnames(DnsName, A) when is_binary(DnsName) ->
    acc_generalnames( {dNSName, binary_to_list(DnsName)}, A);
acc_generalnames( {_, _} = Gn, { Cn, GNs } ) ->
    { Cn, [Gn|GNs] }.

% Given a list of subject names, return a distinguished name for use in
% the certificate subject, and a SubjectAltName extension.
-spec cn_and_ext(list(letsencrypt:subject_name())) -> {term(), #'Extension'{}}.
cn_and_ext(SubjectNames) ->
    {CommonName, SANs} = lists:foldr(fun acc_generalnames/2, {none,[]}, SubjectNames),
    {Attr,Value} =
	case CommonName of
	    none -> {?'id-at-pseudonym', "Server"};
	    DnsName -> {?'id-at-commonName', DnsName}
	end,
    {
      {rdnSequence,
       [[#'AttributeTypeAndValue'{
	    type=Attr,
	    value=public_key:der_encode('DirectoryString', {printableString, Value})}]]},

      #'Extension'{
	 extnID=?'id-ce-subjectAltName',
	 critical= (CommonName == none),
	 extnValue=public_key:der_encode('SubjectAltName',SANs)
	}
    }.

% Converts date+time to a UTCTime or GeneralTime in accordance with
% the rules in RFC5280 for 2 vs. 4 digit years.
-spec pkix_time(calendar:date(),calendar:time()) -> public_key:time().
pkix_time({Y,Mo,Dd},{Hh,Mm,Ss}) ->
    Tail = io_lib:format("~2..0B~2..0B~2..0B~2..0B~2..0BZ",
		     [Mo,Dd,Hh,Mm,Ss]),
    {Tag,Year} =
	if
	    (Y >= 1950) and (Y < 2000) ->
		{ utcTime, io_lib:format("~2..0B", [Y - 1900]) };
	    (Y >= 2000) and (Y < 2050) ->
		{ utcTime, io_lib:format("~2..0B", [Y - 2000]) };
	    true ->
		{ generalTime, io_lib:format("~4..0B", [Y]) }
	end,
    { Tag, lists:flatten([Year,Tail]) }.

% Returns a validity period starting a little before now and extending
% for Hours hours.
-spec validity_around_now(integer()) -> #'Validity'{}.
validity_around_now(Hours) ->
    {Date,{Hh,_,_}} = calendar:universal_time(),
    Nh = Hh + Hours,
    {EndDate, EndH} =
	if
	    Nh < 24 -> { Date, Nh };
	    true -> begin
		     DeltaD = Nh div 24,
		     {
		       calendar:gregorian_days_to_date(calendar:date_to_gregorian_days(Date) + DeltaD),
		       Nh rem 24
		     }
		 end
	end,
    #'Validity'{
       notBefore = pkix_time(Date, {Hh,0,0}),
       notAfter = pkix_time(EndDate, {EndH, 0, 0})
    }.

-spec certificate(string(), binary(), binary(), string()) -> string().
certificate(Domain, DomainCert, IntermediateCert, CertsPath) ->
    FileName = CertsPath++"/"++Domain++".crt",
    %io:format("domain cert: ~p~nintermediate: ~p~n", [DomainCert, IntermediateCert]),
    %io:format("writing final certificate to ~p~n", [FileName]),

    file:write_file(FileName, <<(pem_format(DomainCert))/binary, $\n, IntermediateCert/binary>>),
    FileName.


-spec pem_format(binary()) -> binary().
pem_format(Cert) ->
    <<"-----BEGIN CERTIFICATE-----\n",
      (pem_format(base64:encode(Cert), <<>>))/binary, $\n,
      "-----END CERTIFICATE-----">>.

-spec pem_format(binary(), binary()) -> binary().
pem_format(<<>>, <<$\n, Fmt/binary>>) ->
    Fmt;
pem_format(<<Head:64/binary, Rest/binary>>, Fmt)  ->
    pem_format(Rest, <<Fmt/binary, $\n, Head/binary>>);
pem_format(Rest, Fmt)  ->
    pem_format(<<>>, <<Fmt/binary, $\n, Rest/binary>>).
