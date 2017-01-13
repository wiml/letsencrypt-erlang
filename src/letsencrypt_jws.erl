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

-export([init/1, encode/3, thumbprint/2]).

-include_lib("public_key/include/public_key.hrl").

-spec init(letsencrypt:ssl_privatekey()) -> letsencrypt:jws().
init(#{key := Key = #'RSAPrivateKey'{}}) ->
    #{
        alg => 'RS256',
        jwk =>  jwk(Key),
        nonce => undefined
    }.


-spec encode(letsencrypt:ssl_privatekey(), letsencrypt:jws(), map()) -> binary().
encode(#{key := Key}, Jws, Content) ->
    %io:format("~p~n~p~n", [Jws, Content]),
    Protected = letsencrypt_utils:b64encode(jiffy:encode(Jws)),
    Payload   = letsencrypt_utils:b64encode(jiffy:encode(Content)),
    ToBeSigned = <<Protected/binary, $., Payload/binary>>,

    Sign = case { Key, maps:get(alg, Jws) } of
	       { #'RSAPrivateKey'{modulus=N, publicExponent=E,
				  privateExponent=D}, 'RS256' } ->
		   crypto:sign(rsa, sha256, ToBeSigned, [E,N,D])
	   end,
    Sign2 = letsencrypt_utils:b64encode(Sign),

    jiffy:encode({[
        {header, {[]}},
        {protected, Protected},
        {payload  , Payload},
        {signature, Sign2}
    ]}).


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
    ]}.
