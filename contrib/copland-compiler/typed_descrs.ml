(**
 * Copyright 2020 United States Government
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

(** Module for representing the difference between readable and
    writable file descriptors at the type level. I consistently
    confused the order of the descriptors returned by
    {!val:Unix.pipe}, and it does not seem to be possible to get the
    file descriptor for an {!type:In_channel.t} or
    {!type:Out_channel.t}. So we'll just introduce simple wrapper
    types for file descriptors and appropriate functions.
*)

open Core;;

(** wrapper around a readable Unix.File_descr.t *)
type descr_in = Readable of Unix.File_descr.t

(** wrapper around a writeable Unix.File_descr.t *)
type descr_out = Writeable of Unix.File_descr.t

(** open an input descriptor *)
let open_in f = Readable (Unix.openfile ~mode:[Unix.O_RDONLY] f);;

(** open an output descriptor *)
let open_out f = Writeable (Unix.openfile ~mode:[Unix.O_WRONLY] f);;

(** get the integer backing an input descriptor *)
let in_to_int (Readable r) = Unix.File_descr.to_int r;;

(** get the Unix.File_descr for an input descriptor *)
let in_to_fd (Readable r) = r
    
(** Wrap the given integer up as a readable descriptor. Use of this
    function may lead to runtime failures if the given integer isn't
    really a readable file descriptor. *)
let int_to_in n = Readable (Unix.File_descr.of_int n)
                                
(** get the integer backing an output descriptor *)
let out_to_int (Writeable r) = Unix.File_descr.to_int r;;

(** get the Unix.File_descr for an input descriptor *)
let out_to_fd (Writeable w) = w

(** Wrap the given integer up as a writable descriptor. Use of this
    function may lead to runtime failures if the given integer isn't
    really a readable file descriptor. *)
let int_to_out n = Writeable (Unix.File_descr.of_int n)

(** Close an input descriptor. Consumes all exceptions. *)
let close_in (Readable r) = try Unix.close r with e -> ();;

(** close an output descriptor. Consumes all exceptions. *)
let close_out (Writeable w) = try Unix.close w with e -> ();;

(** Wrapper around Unix.pipe, returns readable and writable descriptors *)
let pipe () = let (read_end, write_end) = Unix.pipe () in
    (Readable read_end, Writeable write_end)

(** Replace standard output with the given output descriptor *)
let dup2out (Writeable w) = Unix.dup2 ~src:w ~dst:Unix.stdout;;

(** Replace standard input with the given readable descriptor *)
let dup2in (Readable r) = Unix.dup2 ~src:r ~dst:Unix.stdin;;

(** Check if two input descriptors are equal **)
let equal_in (Readable r) (Readable s) = Unix.File_descr.equal r s;;

(** Check if two output descriptors are equal **)
let equal_out (Writeable w) (Writeable x) = Unix.File_descr.equal w x;;

(** Wrapper around stdin *)
let stdin = Readable Unix.stdin;;

(** Wrapper around stdout *)
let stdout = Writeable Unix.stdout;;
