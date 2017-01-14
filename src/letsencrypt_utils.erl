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

-module(letsencrypt_utils).
-author("Guillaume Bour <guillaume@bour.cc>").

-export([b64encode/1, ber_get_tlv/2, hexdigest/1, hashdigest/2, bin/1, str/1]).

-type character() :: integer().
-type asn1_tag() :: {universal|application|context|private, primitive|constructed, integer()}.

-spec b64encode(string()|binary()) -> binary().
b64encode(X) ->
    Base64 = base64:encode(X),
    << <<(encode_byte(B)):8>> || <<B:8>> <= Base64, B =/= $= >>.


-spec encode_byte(character()) -> character().
encode_byte($+) -> $-;
encode_byte($/) -> $_;
encode_byte(B) -> B.


-spec hexdigest(string()|binary()) -> binary().
hexdigest(X) ->
    << <<(hex(H)),(hex(L))>> || <<H:4,L:4>> <= X >>.

hex(C) when C < 10 -> $0 + C;
hex(C)             -> $a + C - 10.

% returns hexadecimal digest of SHA256 hashed content
-spec hashdigest(sha256, binary()) -> binary().
hashdigest(sha256, Content) ->
	hexdigest(crypto:hash(sha256, Content)).

-spec bin(binary()|string()) -> binary().
bin(X) when is_binary(X) ->
    X;
bin(X) when is_list(X) ->
    list_to_binary(X);
bin(X) when is_atom(X) ->
    erlang:atom_to_binary(X, utf8);
bin(_X) ->
    throw(invalid).


-spec str(binary()) -> string().
str(X) when is_binary(X) ->
    binary_to_list(X);
str(X) when is_integer(X) ->
    integer_to_list(X);
str(_X) ->
    throw(invalid).


-spec ber_tag(asn1_tag()) -> binary().
ber_tag({Cls,Cnst,Tag}) when Tag < 31 ->
    % Construct the tag byte (we don't support tags greater than 30, so
    % the tag is always 1 byte long).
    << (case Cls of
	    universal -> 0;
	    application -> 1;
	    context -> 2;
	    private -> 3
	end):2/integer,
       (case Cnst of
	    primitive -> 0;
	    constructed -> 1
	end):1/integer,
       Tag:5/integer >>.

% Simple BER parser helper. We assume that the caller is expecting a
% specific tag, so we take it as an arg and fail on a mismatch.
% We also fail on indefinite lengths.
-spec ber_get_tlv(asn1_tag(), binary()) -> { binary(), binary() }.
ber_get_tlv(ExpectedTag, BER) ->
    TagByte = ber_tag(ExpectedTag),
    % Parse the length field, which might be a plain length, or
    % it might be an octet-count followed by that many octets of integer.
    {Length, Rest} = case BER of
			 <<TagByte:1/binary,0:1,L:7,R/binary>> ->
			     {L, R};
			 <<TagByte:1/binary,1:1,0:7,R/binary>> ->
			     {indefinite, R};
			 <<TagByte:1/binary,1:1,LL:7,R/binary>> ->
			     LengthBits = LL * 8,
			     <<L:LengthBits/integer,Rr/binary>> = R,
			     {L, Rr}
		     end,
    % Split the contents off of any following data
    <<Content:Length/binary, Rest2/binary>> = Rest,
    { Content, Rest2 }.
