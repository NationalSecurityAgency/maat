(** * Copyright 2024 United States Government
    *
    * Licensed under the Apache License, Version 2.0 (the "License");
    * you may not use this file except in compliance with the License.
    * You may obtain a copy of the License at
    *
    *     http://www.apache.org/licenses/LICENSE-2.0
    *
    * Unless required by applicable law or agreed to in writing, software
    * distributed under the License is distributed on an "AS IS" BASIS,
    * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    * See the License for the specific language governing permissions and
    * limitations under the License.
    * *)
{
    open Lexing
    open Parser
    exception Error 
}

let white = [' ' '\t']+
let digit = ['0' - '9']
let int = '-'? digit+
let letter = ['a'-'z' 'A'-'Z']
let other_char = ['_' '-' '/' '.']
let id = (other_char | letter | digit) (other_char | letter | digit)*
let endl = ['\n']
let blank = [' ' '\009' '\012']


rule token = parse
    | blank+
        { token lexbuf }
    | endl
        { new_line lexbuf; token lexbuf }
    | "graph"
        { GRAPH }
    | "children"
        { CHILDREN }
    | "->"
        { ARROW }
    | "("
        { LPAREN }
    | ")"
        { RPAREN }
    | "SIG"
        { SIG }
    | "USM"
        { USM }
    | ","
        { COMMA }
    | "["
        { LBRACKET }
    | "]"
        { RBRACKET }
    | "<"
        { SEQBRANCH }
    | "~"
        { CONCBRANCH }
    | id 
        { ID (Lexing.lexeme lexbuf) }
    | eof
        { EOF }
    | _
        { raise Error }