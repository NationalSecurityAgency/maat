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

exception InvalidAspXml

(** A datastructure representing an xml file *)
type xml =
  | Element of string * (string * string) list * xml list
  | Pcdata of string

(** Reads a file and parses it to produce an xml *)
val xml_from_filename : string -> xml

(** Get the children of an xml node *)
val children : xml -> xml list

(** Get the data contained in an xml node *)
val pcdata : xml -> string

(** Returns the lists of attributes contained in an xml node *)
val attribs : xml -> (string * string) list

(** Returns if an xml is an element with a given name *)
val xml_has_name : string -> xml -> bool

(** Returns the data of a single child of an xml node *)
val get_text_child : xml -> string

(** Returns a child xml with a given name *)
val get_element_named : string -> xml -> xml

(** Returns an attribute with a given name *)
val get_attrib_named : string -> xml -> string
