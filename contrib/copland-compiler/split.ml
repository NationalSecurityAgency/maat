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

open Core;;
                                                             
type outspec =
    | All
    | EvenLines
    | OddLines
    | None
    | Pattern of Str.regexp
;;

let handle_line idx line chan =
    let write_line _ = ignore (Out_channel.output_string chan line) in
    function
    | None         -> ()
    | All          -> write_line ()
    | Pattern pat  -> (match Str.string_match pat line 0 with
                               | true -> write_line ()
                               | false -> ())
    | EvenLines    -> if (idx mod 2) = 0 then write_line ()
    | OddLines     -> if (idx mod 2) = 1 then write_line ()
                                                       
let process_input a b = function
    | (None, None)     -> In_channel.input_all In_channel.stdin |> ignore 
    | (All, All)       -> (let input = In_channel.input_all In_channel.stdin in
                           ignore (Out_channel.output_string a input) ;
                           ignore (Out_channel.output_string b input))
    | (None, All)      -> (let input = In_channel.input_all In_channel.stdin in
                           ignore (Out_channel.output_string b input))
    | (All, None)      -> (let input = In_channel.input_all In_channel.stdin in
                          ignore (Out_channel.output_string a input))
    | (spec_a, spec_b) -> In_channel.fold_lines In_channel.stdin ~init:0
                                      ~f:(fun lineno -> fun line ->
                                             handle_line lineno line a spec_a;
                                             handle_line lineno line b spec_b;
                                             lineno + 1)
                                  |> ignore

let cmd =
    let open Command.Param in
    let open Command.Let_syntax in
    let choices side = choose_one
                           [flag (sprintf "--%s-all" side) no_arg ~doc:("pass all input to "^side)
                            |> map ~f:(function true -> Some All  | _ -> None) ;
                            flag (sprintf "--%s-none" side) no_arg ~doc:("pass no input to "^side)
                            |> map ~f:(function true -> Some None  | _ -> None);
                            flag (sprintf "--%s-pattern" side) (optional string)
                                ~doc:("pass lines matching pattern to "^side)
                            |> map  ~f:(function (Some s) -> Some (Pattern (Str.regexp s)) | None -> None);
                            flag (sprintf "--%s-even" side) no_arg ~doc:("pass even lines to "^side)
                            |> map  ~f:(function true -> Some EvenLines | _ -> None);
                            flag (sprintf "--%s-odd" side) no_arg ~doc:("pass even lines to "^side)
                            |> map  ~f:(function true -> Some OddLines | _ -> None)
                           ] (Default_to All) in
    (Command.basic
         ~summary:"Send input to two output file descriptors based on command line arguments"
         (let%map lspec = choices "left"
          and rspec = choices "right"
          and lfd = anon ("leftfd" %: int)
          and rfd = anon ("rightfd" %: int) in
          (fun _ -> (process_input
                         (Unix.out_channel_of_descr (Unix.File_descr.of_int lfd))
                         (Unix.out_channel_of_descr (Unix.File_descr.of_int rfd))
                         (lspec, rspec)))))

let _ = Command.run ~version:"1.0" ~build_info:"RWO" cmd
