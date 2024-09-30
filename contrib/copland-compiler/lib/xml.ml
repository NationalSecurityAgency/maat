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

open Xmlm
open Core
open Poly

exception InvalidAspXml

(** A datastructure representing an xml file *)
type xml =
  | Element of string * (string * string) list * xml list
  | Pcdata of string

(** Reads a file and parses it to produce an xml *)
let xml_from_filename (file : string) : xml =
  let src_input : input =
    make_input ~strip:true (`Channel (Stdlib.open_in file))
  in
  let build_element (((_, local_name), attribs) : tag) (children : xml list) =
    Element
      ( local_name,
        List.map
          ~f:(fun ((_, local_name), value) -> (local_name, value))
          attribs,
        children )
  in
  snd @@ input_doc_tree ~el:build_element ~data:(fun s -> Pcdata s) src_input

(** Get the children of an xml node *)
let children (x : xml) : xml list =
  match x with Element (_, _, xmls) -> xmls | _ -> raise InvalidAspXml

(** Get the data contained in an xml node *)
let pcdata (x : xml) : string =
  match x with Pcdata s -> s | _ -> raise InvalidAspXml

(** Returns the lists of attributes contained in an xml node *)
let attribs (x : xml) : (string * string) list =
  match x with Element (_, attribs, _) -> attribs | _ -> raise InvalidAspXml

(** Returns if an xml is an element with a given name *)
let xml_has_name (name : string) (x : xml) : bool =
  match x with Element (name', _, _) -> name = name' | _ -> false

(** Returns the data of a single child of an xml node *)
let get_text_child (x : xml) : string =
  x |> children |> List.hd |> Option.value_exn |> pcdata

(** Returns a child xml with a given name *)
let get_element_named (name : string) (x : xml) : xml =
  x |> children |> List.find_exn ~f:(xml_has_name name)

(** Returns an attribute with a given name *)
let get_attrib_named (name : string) (x : xml) : string =
  match x with
  | Element (_, attribs, _) ->
      snd @@ List.find_exn ~f:(fun (name', _) -> name = name') attribs
  | _ -> raise InvalidAspXml
