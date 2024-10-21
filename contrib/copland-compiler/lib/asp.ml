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

open Ccode.Primitives
open Core
open Poly
open Xml

(** Information needed to compile an ASP that can be found in an ASP's xml file *)
type asp_t = {
  asp_name : ident;
  uuid : string;
  target_type : ident;
  address_type : ident;
  measurement_type : ident option;
}

exception AspNotFound of string

(** Generates an asp_t value from a properly structured xml *)
let parse_asp_from_xml (x : xml) : asp_t =
  let asp_children = children x in
  let name =
    let name_xml = List.find_exn ~f:(xml_has_name "name") asp_children in
    get_text_child name_xml
  in
  let uuid =
    let uuid_xml = List.find_exn ~f:(xml_has_name "uuid") asp_children in
    get_text_child uuid_xml
  in
  let target, address =
    let measurers_xml =
      List.find_exn ~f:(xml_has_name "measurers") asp_children
    in
    let satisfier_xml =
      List.find_exn ~f:(xml_has_name "satisfier") (children measurers_xml)
    in
    let capability_xml =
      List.find_exn ~f:(xml_has_name "capability") (children satisfier_xml)
    in
    let attributes = attribs capability_xml in
    let target =
      snd @@ List.find_exn ~f:(fun (name, _) -> name = "target_type") attributes
    in
    let address =
      snd
      @@ List.find_exn ~f:(fun (name, _) -> name = "address_type") attributes
    in
    (target, address)
  in
  {
    asp_name = name;
    uuid;
    target_type = target;
    address_type = address;
    measurement_type = None;
  }

(** Take an xml with a top <name> tag and extract its value *)
let parse_name (x : xml) : string =
  let asp_children = children x in
  let name =
    let name_xml = List.find_exn ~f:(xml_has_name "name") asp_children in
    get_text_child name_xml
  in
  name

(** A mutable reference pointing to the directory containing asp source code *)
let asps_dir = ref "../../src/asps"

(** Generates a map from strings to xml data from the xmls present in the asps_dir directory *)
let asps_xmls : xml Util.StringMap.t =
  let open Core_unix in
  let open Util in
  let dir = opendir !asps_dir in
  let rec read_xmls (file : string option) (xmls : xml StringMap.t) =
    match file with
    | None -> xmls
    | Some fname ->
        let xmls' =
          if String.suffix fname 4 = ".xml" then
            let xml = xml_from_filename (sprintf "%s/%s" !asps_dir fname) in
            let name = parse_name xml in
            match StringMap.add xmls ~key:name ~data:xml with
            | `Ok m -> m
            | `Duplicate -> xmls
          else xmls
        in
        read_xmls (readdir_opt dir) xmls'
  in
  let xmls = read_xmls (readdir_opt dir) StringMap.empty in
  let () = closedir dir in
  xmls

(** Generates an asp_t corresponding to [asp_name] provided such an asp is
    defined *)
let get_asp asp_name =
  match Util.StringMap.find asps_xmls asp_name with
  | Some xml -> (
      try parse_asp_from_xml xml
      with _ ->
        raise
        @@ AspNotFound (Printf.sprintf "asp %s maps to invalid xml" asp_name))
  | None -> raise @@ AspNotFound (Printf.sprintf "asp %s not found" asp_name)
