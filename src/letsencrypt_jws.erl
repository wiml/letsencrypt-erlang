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

-module(letsencrypt_jws).
-author("Guillaume Bour <guillaume@bour.cc>").
-author("Wim Lewis <wiml@hhhh.org>").

-export([init/1, encode/3, thumbprint/2]).

-include_lib("public_key/include/public_key.hrl").

-spec init(letsencrypt:ssl_privatekey()) -> letsencrypt:jws().
init(#{key := Key = #'RSAPrivateKey'{}}) ->
    #{
        alg => 'RS256',
        jwk =>  jwk(Key),
        nonce => undefined
     };
init(#{key := Key = #'ECPrivateKey'{}}) ->
    Jwk = jwk(Key),
    SigAlg = case jws_get(crv, Jwk) of
		 'P-256' -> 'ES256';
		 'P-384' -> 'ES384';
		 'P-521' -> 'ES512'   % sic: 521-bit curve, 512-bit hash
	     end,
    #{
        alg => SigAlg,
        jwk => Jwk,
        nonce => undefined
     }.

-spec encode(letsencrypt:ssl_privatekey(), letsencrypt:jws(), map()) -> binary().
encode(#{key := Key}, Jws, Content) ->
    %io:format("~p~n~p~n", [Jws, Content]),
    Protected = letsencrypt_utils:b64encode(jiffy:encode(Jws)),
    Payload   = letsencrypt_utils:b64encode(jiffy:encode(Content)),
    ToBeSigned = <<Protected/binary, $., Payload/binary>>,

    {PKAlg, HashAlg} = alg_get_algpair(jws_get(alg, Jws)),
    {PKAlg, PrivK}   = letsencrypt_ssl:pk_to_cryptok(Key),
    Sign  = crypto:sign(PKAlg, HashAlg, ToBeSigned, PrivK),
    Sign1 = case PKAlg of
		rsa -> Sign;
		ecdsa -> jws_ecdsa_sig_format(jws_get(crv, jws_get(jwk, Jws)), Sign)
	    end,
    Sign2 = letsencrypt_utils:b64encode(Sign1),

    jiffy:encode({[
        {header, {[]}},
        {protected, Protected},
        {payload  , Payload},
        {signature, Sign2}
    ]}).

% Look up the `crypto` algorithm pair represented by a JWS identifier.
-spec alg_get_algpair(atom()) -> {crypto:public_key_algorithms(), crypto:digest_type()}.
alg_get_algpair('RS256') -> {rsa,   sha256};
alg_get_algpair('ES256') -> {ecdsa, sha256};
alg_get_algpair('ES384') -> {ecdsa, sha384};
alg_get_algpair('ES512') -> {ecdsa, sha512}.

-spec thumbprint(letsencrypt:ssl_privatekey(), binary()) -> binary().
thumbprint(#{key := Key}, Token) ->
    % rfc7638 jwk thumbprint
    Thumbprint = jiffy:encode(jwk(Key), [force_utf8]),
    <<Token/binary, $., (letsencrypt_utils:b64encode(crypto:hash(sha256, Thumbprint)))/binary>>.


jwk(#'RSAPrivateKey'{modulus=N, publicExponent=E}) ->
    %NOTE: json payload requires to be encoded in keys alphabetical order
    {[
        {e, letsencrypt_utils:b64encode(binary:encode_unsigned(E))},
        {kty, 'RSA'},
        {n, letsencrypt_utils:b64encode(binary:encode_unsigned(N))}
    ]};
jwk(#'ECPrivateKey'{publicKey=PubPoint, parameters={namedCurve, CurveOid}}) ->
    {Curve,CLen} = case CurveOid of
		       ?'secp256r1' -> {'P-256', 32};
		       ?'secp384r1' -> {'P-384', 48};
		       ?'secp521r1' -> {'P-521', 66}
		   end,
    % PubPoint is encoded in secg ECPoint format, but JWK needs the
    % individual coordinates broken out.
    % ECPoints start with a format byte. Format 04 is the uncompressed
    % point format. Formats 02 and 03 are compressed;
    % in theory we can convert them to uncompressed form, but we
    % don't need to because the crypto app doesn't generate them.
    <<4:8/integer, X:CLen/binary, Y:CLen/binary>> = PubPoint,
    {[
        {crv, Curve},
        {kty, 'EC'},
        {x, letsencrypt_utils:b64encode(X)},
        {y, letsencrypt_utils:b64encode(Y)}
    ]}.

jws_get(K, V) when is_map(V) ->
    maps:get(K, V);
jws_get(K, {Plist}) when is_list(Plist) ->
    {_, V} = proplists:lookup(K, Plist),
    V.

% JWS uses a different format for ECDSA signatures than PKIX formats
% do. The crypto app returns a DER-encoded pair of integers (type
% ECDSA-Sig-Value), but JWS wants a simple concatenation of
% fixed-width octet-string representations, without any header.
-spec jws_ecdsa_sig_format(atom(),binary()) -> binary().
jws_ecdsa_sig_format(Curve, DER) ->
    { Values, <<>> } = letsencrypt_utils:ber_get_tlv( {universal,constructed,16}, DER),
    { R, Other }     = letsencrypt_utils:ber_get_tlv( {universal,primitive,2}, Values),
    { S, <<>> }      = letsencrypt_utils:ber_get_tlv( {universal,primitive,2}, Other),
    BinLen = case Curve of
		 'P-256' -> 32;
		 'P-384' -> 48;
		 'P-521' -> 66
	     end,
    << (fixed_width(BinLen, R))/binary,
       (fixed_width(BinLen, S))/binary >>.
% A DER integer may be longer than the fixed width size (if it requires a
% leading 0 to remain positive) or shorter (if a leading 0 was trimmed).
fixed_width(W, Num) ->
    case Num of
	<<_:W/binary>> -> Num;
	<<0:8, Unsigned:W/binary>> -> Unsigned;
	_ ->
	    Unpadded = byte_size(Num),
	    <<0:(8 * (W - Unpadded))/integer, Num/binary>>
    end.
