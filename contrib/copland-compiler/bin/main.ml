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
 
open Copland_compiler
open Core


(** Top-level command for running the interpreter/compiler. Accepts
    command line arguments: 
    {ul 
    {- "-b": behave as the buffering_asp. see {!val:buffer_input}. Should not be used with "-c"}
    {- "-s": input is in SExp format (default is json)}
    {- "-e": input is on the command line, not read from a file.}
    {- "-c out.c": compile the input workflow to the file "out.c"}
    (- "-x out.xml": generate the input workflow to the file "out.xml")
    {- "input": a filename from which to read the workflow}
    }
*)
let cmd =
  let open Command.Let_syntax in
  let open Command.Param in
  Command.basic ~summary:"Interpret a workflow"
    ~readme:(fun () ->
      "Read a json representation of a workflow from a file and interprete it.")
    (let%map copland_file =
       flag "-f" (required string) ~doc:"file name of file containing copland phrase"
     and args_file =
       flag "-a" (optional string) ~doc:"file name of file containing argument map"
     and cfile = flag "-c" (required string) ~doc:"file name of output file"
     and asps_dir =
       flag "-d"
         (optional (Arg_type.map ~f:(fun s -> s) string))
         ~doc:"directory name of directory containing asp xml files"
     in
     fun () ->
       let open Result in
       let open Result.Let_syntax in
       (let%bind copland_string =
          try_with (fun _ -> In_channel.read_all copland_file)
        in
        let%bind args_string_opt =
          try_with (fun _ -> Option.map ~f:(fun f ->In_channel.read_all f) args_file)
        in
        let%bind copland =
          try_with (fun _ ->
              Parser_wrapper.parse_workflow_from_string copland_string)
        in
        let%bind args =
          try_with (fun _ -> Option.map ~f:(fun args_string -> Parser_wrapper.parse_args_from_string args_string) args_string_opt)
        in
        let%bind () =
          try_with @@ fun _ ->
          Option.iter ~f:(fun dir -> Asp.asps_dir := dir) asps_dir
        in
        Out_channel.flush stderr;
        try_with (fun _ ->
            Out_channel.with_file cfile ~f:(fun chan ->
                Arg_compiler.compile (Option.value ~default:(Util.StringMap.empty) args) copland
                |> Out_channel.output_string chan)))
       |> function
       | Ok _ -> ()
       | Error e ->
           Printf.fprintf stderr "Error: %s\n" (Exn.to_string e);
           Out_channel.flush stderr)

let _ = Command_unix.run ~version:"1.0" ~build_info:"RWO" cmd
