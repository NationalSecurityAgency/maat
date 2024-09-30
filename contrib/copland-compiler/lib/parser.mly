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
%{
    open Copland
    open Copland_factory
    open Util
%}

%token GRAPH
%token CHILDREN
%token ARROW
%token SIG
%token SEQBRANCH
%token CONCBRANCH
%token <string> ID
%token LPAREN
%token RPAREN
%token LBRACKET
%token RBRACKET
%token USM
%token AT
%token EOF
%token COMMA

%start <workflow> parse_workflow_top
%start <workflow * (string list) StringMap.t> parse_workflow_args
%start <(string list) StringMap.t> parse_args_top
%%

parse_args_top :
    | m = parse_arg_map; EOF
        { m }

parse_workflow_args:
    | w = parse_workflow; m = parse_arg_map; EOF
        { (w,m) }

parse_workflow_top:
    | w = parse_workflow; EOF
        { w }

parse_workflow:
    | LPAREN; w = workflow; RPAREN
        { w }
    | w = workflow
        { w }

workflow:
    | a = atomic
        { a }
    | AT; place = ID; wf = workflow
        { make_at place wf }
    | LPAREN; wf1 = workflow; ARROW; wf2 = workflow; RPAREN
        { make_arrow wf1 wf2 }
    | LPAREN; wf1 = workflow; SEQBRANCH; wf2 = workflow; RPAREN
        { make_seq_branch wf1 wf2 }
    | LPAREN; wf1 = workflow; CONCBRANCH; wf2 = workflow; RPAREN
        { make_conc_branch wf1 wf2 }
    | SIG
        { make_sig }

atomic:
    | USM; asp = ID; GRAPH; args = list(argument)
        { make_usm asp "graph" args }
    
argument:
    | arg = ID
        { arg }
    | CHILDREN
        { "children" }


parse_arg_map:
    | LPAREN; arg_map = list(arg_map_entry); RPAREN
        { make_arg_map arg_map }

arg_map_entry:
    | arg_name = ID; LPAREN; args = list(argument); RPAREN
        { (arg_name, args) }