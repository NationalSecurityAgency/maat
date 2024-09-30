(**
 * Copyright 2024 United States Government
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
 *
 *)

(** Contains functions to simplify calling generated code for the parser *)


open Lexing

let parse_workflow_from_string s =
  let lexbuf = from_string s in
  Parser.parse_workflow_top Lexer.token lexbuf

let parse_workflow_from_xml s =
  let open Xml in
  let apb_xml = xml_from_filename s in
  let wf_string =
    apb_xml
    |> get_element_named "copland"
    |> get_element_named "phrase" |> get_attrib_named "copland"
  in
  parse_workflow_from_string wf_string

let parse_copland_from_string s =
  let lexbuf = from_string s in
  Parser.parse_workflow_args Lexer.token lexbuf

let parse_args_from_string s =
  let lexbuf = from_string s in
  Parser.parse_args_top Lexer.token lexbuf
