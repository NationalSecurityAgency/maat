(**
 * Copyright 2023 United States Government
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

(** Example ocaml code illustrating initial thinking on Copland
    execution. This isn't intended as real code, just a reference.

    Please do not read too much into the structure or correctness of
    this code.

    Uses the Janestreet Core module (mostly Core.Unix),
    and PPX Deriving Std and Yojson
*)
open Core;;

(** A splitter ASP is a command that accepts file descriptors
    representing the write-end of the pipes connecting it to the left
    and right successors and redirects its input to these to output
    channels based on some internal logic.

    The static arguments to a splitter ASP are either a simple
    string, a placeholder for the left child's pipe or a placeholder
    for the right child's pipe.
*)
type split_asp = {cmd : string;
                  args : split_arg list}
and split_arg = SArg of string | ToLeft | ToRight
[@@deriving show,yojson,sexp];;

(** A merge ASP is dual to a split ASP, it takes two input channels
    that are the output of the two subprocesses and merges them intoa
    single output stream.

    The static arguments to a merge ASP are either a simple string, a
    placeholder for the left child's pipe or a placeholder for the
    right child's pipe.
*)
type merge_asp = {cmd : string;
                  args : merge_arg list}
and merge_arg = MArg of string | FromLeft | FromRight
[@@deriving show,yojson,sexp];;

(** Used by {!const:workflow.LIN} and {!const:workflow.BRNCH} to
    control the synchronization of subflows. {!const:exec_flow.CONC}
    denotes concurrent execution, {!const:exec_flow.SEQ} denotes
    sequential. *)
type exec_flow =
    | CONC
    | SEQ
[@@deriving show,yojson,sexp];;

(** The workflow type is at the heart of everything and is intended to
    vaguely resemble the structure of Copland terms. The four constructors
    should be interpreted as follows:
    {ul
    {- {!const:workflow.PRIM}: just runs a command with a target and
    command line arguments (Primitive)}

    {- {!const:workflow.LIN}: run two workflows with the output of the
    first sent to the input of the second (Linear)}

    {- {!const:workflow.BRNCH}: run two workflows in parallel,
    splitting the input using a split ASP and merging the output with
    a merge ASP}

    {- {!const:workflow.Sequential}: run one workflow after another,
    split the input using a split ASP and merge the output with a
    merge ASP}
    }
*)
type workflow =
    | PRIM of atomic_flow
    | LIN of exec_flow * linear_flow
    | BRNCH of exec_flow * branching_flow
    | AT of string * workflow
and atomic_flow = {cmd : string;
                   target: string;
                   args : string list}
and
    linear_flow = {first : workflow;
                   second : workflow}
and
    branching_flow = {split : split_asp;
                      left  : workflow;
                      right : workflow;
                      merge : merge_asp}
    [@@deriving show,yojson,sexp];;

(** Actions module signature, modules of this type can be passed to
    the {!module:Evaluation} functor to provide concrete semantics for
    the primitive terms of workflows, the {!val:Evaluation.eval}
    handles the structural decomposition.

    There are two implementations of this signature, one for
    {!module:Interpreter} and one for {!module:Compiler}. The
    interpreter uses a state of type {!type:unit} and uses the
    {!module:Core.Unix} module to create file descriptors and
    fork/exec subprocesses. The compiler uses the {!module:Ccode}
    module to generate compilable C code implementing the workflow.
*)
module type Actions = sig
    (** State type used by the implementation. *)
    type t;;

    (** Type representing PIDs of child processes *)
    type pid;;

    (** Type representing readable file descriptors *)
    type infd;;

    (** Type representing writable file descriptors *)
    type outfd;;

    (** Type representing command line argument for child processes *)
    type arg;;

    (** Type signature for a workflow evaluation
        function. {val:Evaluation.eval} matches this
        signature. Takes lists of file descriptors to close, file
        descriptors to use for stdin and stdout, the workflow to
        evaluate, the current state, and returns a list of child
        pids to wait on and a new state *)
    type evaluator = close_inputs:infd list -> close_outputs:outfd list ->
        stdin:infd -> stdout:outfd -> workflow -> (t, pid list, t) State.t;;

    (** Convert an ocaml string to a command line argument. *)
    val arg_of_string : string -> arg;;

    (** Generate an argument list for a split ASP by replacing
        {!const:split_arg.ToLeft} {!const:split_arg.ToRight} elements
        with the appropriate file descriptors (converted to
        {!type:arg} and unwrapping the {!const:split_arg.SArg}
        elements. *)
    val substitute_split_args : outfd -> outfd -> split_arg list -> (t, arg list, t) State.t;;

    (** Same as {!val:substitute_split_args} but for {!type:merge_arg} lists. *)
    val substitute_merge_args : infd -> infd -> merge_arg list -> (t, arg list, t) State.t;;

    (** Initialize a new state *)
    val init : unit -> t;;

    (** Create a pipe with the given identifier (the identifier may be ignored) *)
    val pipe : string -> (t, (infd * outfd), t) State.t;;

    (** Execute an ASP, the child process must first close the given
        file descriptors, then dup2() the standard input and standard
        output descriptors to stdin and stdout, then call exec() on the
        cmd argument with the list of arguments. Should return the PID of
        the new child (and a new state).
    *)
    val runasp : ?close_inputs:(infd list) -> ?close_outputs:(outfd list) ->
        ?target:string -> stdin:infd -> stdout:outfd -> string -> (arg list) -> (t, pid, t) State.t;;

    (** Wait for a child to exit. Discard the exit status *)
    val wait      : pid -> (t, unit, t) State.t;;

    (** Close a readable file descriptor *)
    val close_in  : infd -> (t, unit, t) State.t;;

    (** Close a writeable file descriptor *)
    val close_out : outfd -> (t, unit, t) State.t;;

    (** Return standard input *)
    val stdin : (t, infd, t) State.t;;

    (** Return standard output *)
    val stdout : (t, outfd, t) State.t;;

    (** Return a readable file descriptor for /dev/null *)
    val devnull_in : (t, infd, t) State.t;;

    (** Return a writeable file descriptor for /dev/null *)
    val devnull_out : (t, outfd, t) State.t;;

    (** Convert a state to a string. For the compiler, this will
        generate the compilable C code implementing the workflow. For the
        interpreter, it just returns the empty string. *)
    val to_string : t -> string;;

    (** Send execute ASP should be use to handle {!const:workflow.At}
        forms. It's not properly implemented anywhere. *)
    val send_execute_asp : string -> evaluator -> evaluator;;

    (** The Buffering ASP is used to handle {!const:workflow.Serial} forms. The
        {!type:evaluator} argument is {!val:Evaluation.eval_subflow}
        and is expected to be used to recur on the second argument
        part of the {!const:workflow.Serial} once the buffering is in
        place. This makes more sense with examples. *)
    val buffering_asp : evaluator -> evaluator;;
end

(** Functor implementing structural evaluation of workflows. Takes an
    {!module:Actions} module providing the necessary primitives to
    implement a compiler or interpreter (or other?) *)
module Evaluation (A: Actions) = struct
    open State;;

    (** Main workhorse function of evaluation (has type
        {!type:A.evaluator}). Used to walk a subflow and call primitives
        from {!module:A} as needed. *)
    let rec eval_subflow ~close_inputs ~close_outputs ~stdin ~stdout =
        let eval_branching ~order {split;left;right;merge} =
            (let%bind (left_in, to_left)      = A.pipe "inl_pipe" in
             let%bind (right_in, to_right)    = A.pipe "inr_pipe" in
             let%bind (from_left, left_out)   = A.pipe "outl_pipe" in
             let%bind (from_right, right_out) = A.pipe "outr_pipe" in
             let%bind dvout                   = A.devnull_out in
             let%bind split_args              = A.substitute_split_args to_left to_right split.args in
             let%bind split_pid               = A.runasp
                                                    ~close_inputs:(left_in::right_in::from_left::from_right::close_inputs)
                                                    ~close_outputs:(stdout::left_out::right_out::close_outputs)
                                                    ~stdin ~stdout:dvout split.cmd
                                                    split_args in
             let%bind dvin                    = A.devnull_in in
             let%bind merge_args              = A.substitute_merge_args from_left from_right merge.args in
             let%bind merge_pid               = A.runasp
                                                    ~close_inputs:(stdin::left_in::right_in::close_inputs)
                                                    ~close_outputs:(left_out::right_out::to_left::to_right::close_outputs)
                                                    ~stdin:dvin ~stdout merge.cmd
                                                    merge_args in
             let%bind left_pids               = eval_subflow
                                                    ~close_inputs:(stdin::right_in::from_right::from_left::close_inputs)
                                                    ~close_outputs:(stdout::to_right::right_out::to_left::close_outputs)
                                                    ~stdin:left_in ~stdout:left_out left in
             let%bind left_pids               = (match order with
                                                     | CONC -> return left_pids
                                                     | SEQ  -> (iter ~f:A.wait left_pids
                                                               >>= fun _ -> return [])) in
             let%bind right_pids              = eval_subflow
                                                    ~close_inputs:(stdin::left_in::from_left::from_right::close_inputs)
                                                    ~close_outputs:(stdout::to_left::left_out::to_right::close_outputs)
                                                    ~stdin:right_in ~stdout:right_out right in
             let%bind _                       = A.close_out to_left in
             let%bind _                       = A.close_in left_in in
             let%bind _                       = A.close_out to_right in
             let%bind _                       = A.close_in right_in in
             let%bind _                       = A.close_out left_out in
             let%bind _                       = A.close_in from_left in
             let%bind _                       = A.close_out right_out in
             let%bind _                       = A.close_in from_right in
             return (split_pid::merge_pid::(left_pids @ right_pids))) in
        let eval_linear eval_second {first; second} =
            (let%bind (pipe_read, pipe_write) = A.pipe "pipe" in
             let%bind left_pids               = eval_subflow
                                                    ~close_inputs:(pipe_read::close_inputs)
                                                    ~close_outputs:(close_outputs)
                                                    ~stdin ~stdout:pipe_write first in
             let%bind _                       = A.close_out pipe_write in
             let%bind right_pids              = eval_second
                                                    ~close_inputs:(close_inputs)
                                                    ~close_outputs:(close_outputs)
                                                    ~stdin:pipe_read ~stdout second in
             let%bind _                       = A.close_in  pipe_read in
             return (left_pids @ right_pids)) in
        (function
            | BRNCH (order, flow)      -> eval_branching ~order flow
            | PRIM {cmd; target; args} -> (A.runasp ~close_inputs ~close_outputs
                                               ~target ~stdin ~stdout cmd (List.map ~f:A.arg_of_string
                                                                       (args))
                                         >|= fun pid_ident -> [pid_ident])
            | LIN (CONC, flow)      -> eval_linear eval_subflow flow
            | LIN (SEQ, flow)       -> eval_linear (A.buffering_asp eval_subflow) flow
            | AT  (s,w)             -> A.send_execute_asp s eval_subflow
                                           ~close_inputs ~close_outputs ~stdin ~stdout w)


    (** Top-level evaluation function. Calls {!val:eval_subflow} on a
        state returned by {!A.init}, appends {!A.wait} calls for all
        children, then stringifies the final state. *)
    let eval w =
        eval (let%bind stdin = A.stdin in
              let%bind stdout = A.stdout in
              eval_subflow ~close_inputs:[] ~close_outputs:[]
                  ~stdin:stdin ~stdout:stdout w
              >>= iter ~f:A.wait
              >>= fun _ -> get)
            (A.init ())
        |> A.to_string
end

(** Interpret workflows *)
module Interpreter = Evaluation(struct
        (** Interpreter Actions module. Maintains no internal state,
            all primitives are mapped to appropriate OCaml calls to
            execute the workflow as it happens *)
        type t     = unit;; (** No state to maintain. *)
        type pid   = Pid.t;; (** pids are raw ocaml pids *)
        type infd  = Typed_descrs.descr_in;; (** readable descriptors *)
        type outfd = Typed_descrs.descr_out;; (** writable descriptors *)
        type arg   = string;; (** command line arguments are just ocaml strings *)

        type evaluator = close_inputs:infd list -> close_outputs:outfd list -> stdin:infd -> stdout:outfd -> workflow -> t -> (pid list * t);;

        (** Just return the string *)
        let arg_of_string s = s;;

        (** Helpful binding of {!val:State.return}. Since {!type:t} =
            {!type:unit}, most operations are just going to use this. *)
        let return = State.return

        (** Stringify the numeric file descriptors for
            {!const:split_arg.ToLeft} and {!const:split_arg.ToRight}. *)
        let substitute_split_args to_left to_right argl =
            argl
            |> List.map ~f:(function
                               | SArg s -> s
                               | ToLeft -> Printf.sprintf "%d" (Typed_descrs.out_to_int to_left)
                               | ToRight -> Printf.sprintf "%d" (Typed_descrs.out_to_int to_right))
            |> return
        ;;

        (** Same as {!val:substitute_split_args} but for
            {!const:merge_arg.FromLeft} and {!const:merge_arg.FromRight}. *)
        let substitute_merge_args from_left from_right argl =
            argl
            |> List.map ~f:(function
                               | MArg s -> s
                               | FromLeft -> Printf.sprintf "%d" (Typed_descrs.in_to_int from_left)
                               | FromRight -> Printf.sprintf "%d" (Typed_descrs.in_to_int from_right))
            |> return
        ;;

        (** Nothin to do here, just return unit. *)
        let init () = ();;

        (** Wrapper around {!val:Core.Unix.pipe} via {!val:Typed_descrs.pipe} *)
        let pipe _ = return (Typed_descrs.pipe ())

        (** Use {!val:Core.Unix.fork} and {!val:Core.Unix.exec} to run
            the given command. Return the {!type:Pid.t} of the child. *)
        let runasp ?close_inputs:(close_inputs = []) ?close_outputs:(close_outputs = [])
               ?target:(target = "") ~stdin:(input : Typed_descrs.descr_in) ~stdout:(output : Typed_descrs.descr_out) cmd argv =
            let open Typed_descrs in
            match Unix.fork () with
            | `In_the_child -> (List.iter ~f:close_in close_inputs ;
                                List.iter ~f:close_out close_outputs ;
                                if not (Typed_descrs.equal_in input stdin)
                                then (dup2in input ;
                                      close_in input) ;
                                if not (Typed_descrs.equal_out output stdout)
                                then (dup2out output ;
                                      close_out output );
                                match target with
                                | "" -> ignore (Unix.exec ~prog:cmd ~argv:(cmd::argv) ()); return (Unix.getpid ())
                                | _  -> ignore (Unix.exec ~prog:cmd ~argv:(cmd::target::argv) ()); return (Unix.getpid ())
                                (* exec never returns, calling getpid here makes
                                   the type checker happy *)
                               )
            | `In_the_parent p -> return p;;

        (** wrapper around {!val:Core.Unix.waitpid} *)
        let wait p = ignore (Unix.waitpid p) |> return

        (** wrapper around {!val:Core.Unix.close} via {!val:Typed_descrs.close}*)
        let close_in i = return (Typed_descrs.close_in i);;
        (** wrapper around {!val:Core.Unix.close} via {!val:Typed_descrs.close} *)
        let close_out o = return (Typed_descrs.close_out o);;

        (** wrapper around {!val:Core.Unix.open} via {!val:Typed_descrs.open_in}
            FIXME: this leaks file descriptors.  *)
        let devnull_in = return (Typed_descrs.open_in "/dev/null");;

        (** wrapper around {!val:Core.Unix.open_out} via {!val:Typed_descrs.open_out}.
            FIXME: this leaks file descriptors. *)
        let devnull_out = return (Typed_descrs.open_out "/dev/null");;

        (** wrapper around {!val:Core.Unix.stdin} via {!val:Typed_descrs.stdin}. *)
        let stdin = return Typed_descrs.stdin;;

        (** wrapper around {!val:Core.Unix.stdout} via {!val:Typed_descrs.stdout}. *)
        let stdout = return Typed_descrs.stdout;;

        (** Nothing to do here *)
        let to_string () = "";;

        (** We'll just assume that there exists some ASP called
            "send_execute_asp" that expects a SExp form of a workflow and
            the target name and just does the right thing. So we just
            replace the At form with a corresponding Asp form and
            allow the evaluator to reduce that.
        *)
        let send_execute_asp s eval ~close_inputs ~close_outputs ~stdin ~stdout w =
            eval ~close_inputs ~close_outputs ~stdin ~stdout (PRIM {cmd = "send_execute_asp";
                                                                    target = s;
                                                                    args = [Sexp.to_string (sexp_of_workflow w)]})

        (** Buffering is a little trickier. Like the
            {!val:requestor_asp} we replace the form with an ASP call,
            but this time the ASP is another instance of the
            interpreter with the "-b" flag passed. The "-b" flag
            causes the child interpreter to process to slurp its input
            into a buffer and then fork a grandchild to actually
            interpret its argument while the child flushes the buffer
            to a pipe. This is implemented by {!val:buffer_input}.

            Note: we cheat here a little bit and use `-b` as the
            target of the ASP.
        *)
        let buffering_asp eval ~close_inputs ~close_outputs ~stdin ~stdout w =
            eval ~close_inputs ~close_outputs ~stdin ~stdout (PRIM {cmd = (Sys.get_argv ()).(0);
                                                                    target = "-b";
                                                                    args = ["-e"; "-s"; Sexp.to_string (sexp_of_workflow w)]})
    end)

(** Compile workflows to compilable C code. *)
module Compiler = Evaluation(struct
        (** Compiler module Actions body, instead of executing the
            {!type:workflow} we want to generate compilable C source
            code implementing it. This uses the state type to maintain
            the partially build C function (of type
            {!type:Ccode.pfunc}) and the file descriptors for reading
            and writing /dev/null.

            The generated code depends on C functions for {i runasp()} and {i
            fork_and_buffer()}. See {b runasp.c} for example implementations.
        *)
        open State
        open Ccode.Primitives;;

        type arg = expr;; (** ASP command line arguments are expression in the generated C code *)
        type pid = expr;; (** PIDs are variables (expressions) in the generated code *)
        type infd = expr;; (** file descriptors are variables (expressions) in the generated code *)
        type outfd = expr;; (** file descriptors are variables (expressions) in the generated code *)

        (** The state is a triple of [(readable /dev/null, writeable /dev/null, partially build function)] *)
        type t = infd * outfd * Ccode.pfunc;;

        type evaluator = close_inputs:infd list -> close_outputs:outfd list -> stdin:infd -> stdout:outfd -> workflow -> t -> (pid list * t);;

        (** stdin is the C macro {i STDIN_FILENO} *)
        let stdin = return (EnumLit "STDIN_FILENO");;

        (** stdout is the C macro {i STDOUT_FILENO} *)
        let stdout = return (EnumLit "STDOUT_FILENO");;

        (** the readable devnull fd is tracked in the internal state *)
        let devnull_in = get >|= fun (ni,_,_) -> ni

        (** the writable devnull fd is tracked in the internal state *)
        let devnull_out = get >|= fun (_, no, _) -> no

        (** convert a function that operates on {!type:Ccode.pfunc} states to a
            function that operates on {!type:t} states. *)
        let liftf (f : Ccode.pfunc -> ('a * Ccode.pfunc)) =
            get
            >>= fun (ni, no, pf) -> put pf
            >>= fun _ -> f
            >>= fun x -> get
            >>= fun pf -> put (ni,no,pf)
            >|= fun _ -> x

        (** Command line arguments that are constant OCaml strings are
            string literals in the generated C code. *)
        let arg_of_string s = StringLit s;;

        (** Substituting split args requires generating code to
            stringify the {i int} file descriptor.  The returned list
            of {!type:arg} will have the identifiers for the
            stringified values inserted for {!const:split_arg.ToLeft}
            and {!const:split_arg.ToRight}. *)
        let substitute_split_args to_left to_right argl=
            let%bind to_left_str = liftf (Ccode.make_string_of_int to_left) in
            let%map to_right_str = liftf (Ccode.make_string_of_int to_right) in
            List.map ~f:(function
                            | SArg s  -> StringLit s
                            | ToLeft  -> to_left_str
                            | ToRight -> to_right_str) argl
        ;;

        (** Same as {!val:substitute_split_args} but for {!type:merge_arg} *)
        let substitute_merge_args from_left from_right argl =
            let%bind from_left_str = liftf (Ccode.make_string_of_int from_left) in
            let%map from_right_str = liftf (Ccode.make_string_of_int from_right) in
            List.map ~f:(function
                            | MArg s -> StringLit s
                            | FromLeft -> from_left_str
                            | FromRight -> from_right_str) argl

        (** Generate some C code to call the quasi-builtin {i runasp} function. *)
        let runasp ?close_inputs:(close_inputs = []) ?close_outputs:(close_outputs = [])
                   ?target:(target = "") ~stdin ~stdout asp args =
            liftf (Ccode.make_runasp_pf (close_inputs@close_outputs@[IntLit (-1)]) stdin stdout asp target args);;

        (** Generate C code to call {i pipe} *)
        let pipe (n : string) = liftf (Ccode.make_pipe_pf n)

        (** Generate C code to call {i wait} *)
        let wait p       = liftf (Ccode.make_waitpid_pf p) >|= fun _ -> ()

        (** Generate C code to call {i close} *)
        let close_in fd  = liftf (Ccode.make_close_pf fd)

        (** Generate C code to call {i close} *)
        let close_out fd = liftf (Ccode.make_close_pf fd)

        (** initiailize a new state by creating a {!type:Ccode.pfunc}
            and opening file descriptors for reading/writing /dev/null *)
        let init () =
            eval
                (let%bind ni = Ccode.make_open_pf "devnull_in" (StringLit "/dev/null") (EnumLit "O_RDONLY") in
                 let%bind no = Ccode.make_open_pf "devnull_out" (StringLit "/dev/null") (EnumLit "O_WRONLY") in
                 let%map  pf = get in
                 (ni, no, pf))
                (Ccode.mkpfunc ~name:"apb_execute" ~args:[("struct apb", "*apb");
                                                          ("struct scenario", "*scen UNUSED");
                                                          ("uuid_t", "meas_spec UNUSED");
                                                          ("int", "peerchan");
                                                          ("int", "resultchan");
                                                          ("char", "*target UNUSED");
                                                          ("char", "*target_type UNUSED");
                                                          ("struct key_value", "**arg_list UNUSED");
                                                          ("int", "argc UNUSED")]
                     ~rc:"rc" ())

        (** Convert the fully built function to compilable C code. *)
        let to_string (_, _, pf) = Ccode.(c_of_pfunc {pf with stmts = (Return (Var pf.rcvar))::pf.stmts})

        (** Same as {!val:Workflow.Interpreter.send_execute_asp} assumes an ASP,
            "send_execute_asp" exists for doing all the work *)
        let send_execute_asp s eval ~close_inputs ~close_outputs ~stdin ~stdout w =
            eval ~close_inputs ~close_outputs ~stdin ~stdout (PRIM {cmd = "send_execute_asp";
                                                                    target = s;
                                                                    args = [Sexp.to_string (sexp_of_workflow w)]})

        (** Buffering ASP uses the {i fork_and_buffer} quasi-builtin
            to fork subprocesses to perform the buffering and execute the
            se cond subflow.

            {i fork_and_buffer} returns twice. It returns {i > 0} in
            the original process and {i == 0} in the child that should
            expect to receive the buffered input via a pipe. The
            generated code will look something like:

            {v
               rc = fork_and_buffer(&child, &readfd, fds_to_close);
               if(rc < 0)\{
                  /* handle errors */
               \}
               if(rc == 0)\{
                  /* in the grandchild */
                  /* compilation of workflow w */
                  return 0;
                  /* error handling */
                  return -1;
                  /* child never gets passed this point */
               \}
               /* remainder of enclosing workflow executed in parent */
             v}
        *)
        let buffering_asp (evalflow : evaluator) ~close_inputs ~close_outputs ~stdin ~stdout w =
            let open Ccode in
            let%bind ni      = devnull_in in
            let%bind no      = devnull_out in
            let%bind counter = liftf get_counter in
            let%bind rcvar   = liftf get_rcvar in
            let%bind (childpid, bufpiperead) = liftf (make_fork_and_buffer_pf stdin (close_inputs@close_outputs)) in
            let (_,_,child_body) = eval (evalflow ~close_inputs:[] ~close_outputs:[]
                                             ~stdin:bufpiperead ~stdout w
                                         >>= fun pids -> close_in bufpiperead
                                         >>= fun _ -> iter ~f:wait pids
                                         >>= fun _ -> liftf (append_statement (Return (IntLit 0)))
                                         >>= fun _ -> get)
                                       (ni, no, mkpfunc ~name:"ignored" ~args:[] ~rc:"rc" ~counter:counter ()) in
            let%bind _ = liftf (append_statement (If (BinExpr (Eq, (Var rcvar), IntLit 0),
                                                      Seq (stmt_of_pf child_body, Return (IntLit (-1))),
                                                      None))) in
            let%map _ = liftf (put_counter child_body.counter) in
            [childpid]
    end)

module GraphBuilder : Actions = struct
        open State;;

        type edge = | DataFlow of string * (int option) * (int option)
                    | Synchronization of (int option) * (int option);;
        type t = {nodes : (int * (string * string list)) list;
                  subgraphs : (string * t) list;
                  next_node_id : int;
                  edges : (int * edge) list;
                  next_edge_id : int;
                  wait_stack : int list}

        type infd = int;;
        type outfd = int;;
        type pid = int;;
        type arg = | Arg of string | InLeft of int | InRight of int | OutLeft of int | OutRight of int;;
        type evaluator = close_inputs:infd list -> close_outputs:outfd list -> stdin:infd -> stdout:outfd -> workflow -> t -> (pid list * t);;

        let arg_of_string s = Arg s;;
        let string_of_arg = function
            | Arg s      -> s
            | InLeft _   -> "<left>"
            | InRight _  -> "<right>"
            | OutLeft _  -> "<left>"
            | OutRight _ -> "<right>"

        let return = State.return;;

        let substitute_split_args l r ss = return (List.map ~f:(function | SArg s -> Arg s
                                                                         | ToLeft -> OutLeft l
                                                                         | ToRight -> OutRight r) ss);;

        let substitute_merge_args l r ms = return (List.map ~f:(function | MArg m -> Arg m
                                                                         | FromLeft -> InLeft l
                                                                         | FromRight -> InRight r) ms);;


        let get_node_id = (let%bind g = get in
                           let%bind _ = put {g with next_node_id = g.next_node_id + 1} in
                           return g.next_node_id)
        let set_next_node_id nid = (let%bind g = get in
                                    put {g with next_node_id = nid})

        let get_edge_id = (let%bind g = get in
                           let%bind _ = put {g with next_edge_id = g.next_edge_id + 1} in
                           return g.next_edge_id)

        let set_edge_d eid = (let%bind g = get in
                              put {g with next_edge_id = eid})

        let new_node cmd args =
            let%bind nid = get_node_id in
            let%bind g   = get in
            let%bind _   = put {g with nodes = (nid, (cmd,args))::g.nodes} in
            return nid

        let new_edge e = (let%bind eid = get_edge_id in
                          let%bind g = get in
                          let%bind _ = put {g with edges = (eid,e)::g.edges} in
                          return eid);;

        let get_edge eid = (let%bind g = get in
                            return (List.Assoc.find ~equal:(=) g.edges eid))

        let set_edge eid e = (let%bind g = get in
                              put {g with edges = List.Assoc.add ~equal:(=) g.edges eid e})

        let push_wait we = (let%bind g = get in
                           put {g with wait_stack = we::g.wait_stack})

        let consume_waits ~f = (let%bind g = get in
                                let%bind _ = State.iter ~f:f g.wait_stack in
                                let%bind g = get in
                                put {g with wait_stack = []})

        let update_edge_dest eid target = match%bind get_edge eid with
            | Some (DataFlow (lbl, src, _))   -> set_edge eid (DataFlow (lbl, src, Some target))
            | Some (Synchronization (src, _)) -> set_edge eid (Synchronization (src, Some target))
            | None                            -> failwith (sprintf "Undefined edge %d" eid)

        let update_edge_src eid target = match%bind get_edge eid with
            | Some (DataFlow (lbl, _, dst))   -> set_edge eid (DataFlow (lbl, Some target, dst))
            | Some (Synchronization (_, dst)) -> set_edge eid (Synchronization (Some target, dst))
            | None                            -> failwith (sprintf "Undefined edge %d" eid)

        let init () = {nodes = [(0, ("extern_source", []));
                                (1, ("extern_sink", []))] ;
                       subgraphs = [];
                       next_node_id = 2;
                       edges = [
                           (0, DataFlow ("stdin", Some 0, None));
                           (1, DataFlow ("stdout", None, Some 1))];
                       next_edge_id = 2;
                       wait_stack = []
                      };;
        let pipe label =
            let%bind eidx = new_edge (DataFlow (label, None, None)) in
            return (eidx,eidx)

        let close_out _ = return ()
        let close_in _ = return ()
        let wait p = (let%bind we = new_edge (Synchronization (Some p, None)) in
                      let%bind _  = push_wait we in
                      return ())

        let runasp ?close_inputs ?close_outputs ?target:(target="") ~stdin ~stdout cmd (args : arg list) =
            let%bind pid           = new_node cmd (List.map ~f:string_of_arg args) in
            let%bind _             = update_edge_dest stdin pid in
            let%bind _             = update_edge_src stdout pid in
            let gen_args targ argv = match targ with
                                     | "" -> argv
                                     | _  -> (Arg targ)::argv in
            let al                 = gen_args target args in
            let%bind _   = State.iter al
                               ~f:(function | Arg _        -> return ()
                                            | InLeft eid   -> update_edge_dest eid pid
                                            | InRight eid  -> update_edge_dest eid pid
                                            | OutLeft eid  -> update_edge_src eid pid
                                            | OutRight eid -> update_edge_src eid pid) in
            let%bind _   = consume_waits ~f:(fun w -> update_edge_dest w pid) in
            return pid

        let stdin = return 0;;
        let stdout = return 1;;
        let devnull_in = new_edge (DataFlow ("devnull_in", None, None));;
        let devnull_out = new_edge (DataFlow ("devnull_out", None, None));;

        let to_string g = let b = Buffer.create 1024 in
            let cluster_idx = ref 0 in
            let rec helper indent g =
                List.iter g.nodes ~f:(fun (nid, (cmd, args)) ->
                                         bprintf b "%s%d [label=\"%s %s\"]\n" indent nid
                                             cmd (String.concat ~sep:" " (List.map ~f:String.escaped args)));
                List.iter g.subgraphs ~f:(fun (tgt, sg) ->
                                             bprintf b "%ssubgraph cluster_%d {\n" indent (!cluster_idx);
                                             cluster_idx := (!cluster_idx) + 1;
                                             bprintf b "\t%slabel = \"%s\"\n" indent tgt;
                                             bprintf b "\t%scolor=blue\n" indent;
                                             helper (indent^"\t") sg ;
                                             bprintf b "%s}\n" indent) ;
                List.iter g.edges ~f:(function
                                         | (_, DataFlow (lbl, Some src, Some dst)) ->
                                             bprintf b "%s%d -> %d [label=\"%s\"]\n" indent src dst lbl
                                         | (_, Synchronization (Some src, Some dst)) ->
                                             bprintf b "%s%d -> %d [style=dotted]\n" indent src dst
                                         | _ -> ())
            in
            bprintf b "digraph copl {\n";
            helper "\t" g;
            bprintf b "}\n";
            Buffer.contents b

        (* fixme: use subgraphs to support @ notation *)
        let send_execute_asp tgt eval ~close_inputs ~close_outputs ~stdin ~stdout w =
            let%bind g    = get in
            let%bind _    = put {nodes = []; subgraphs = []; next_node_id = g.next_node_id;
                                 edges = g.edges;
                                 next_edge_id = g.next_edge_id;
                                 wait_stack = g.wait_stack} in
            let%bind pids = eval ~close_inputs ~close_outputs ~stdin ~stdout w in
            let%bind sg   = get in
            let%bind _    = put {g with subgraphs    = (tgt,{sg with edges = []})::g.subgraphs ;
                                        next_node_id = sg.next_node_id;
                                        next_edge_id = sg.next_edge_id;
                                        edges        = sg.edges;
                                        wait_stack   = sg.wait_stack} in
            return pids

        let buffering_asp eval ~close_inputs ~close_outputs ~stdin ~stdout w =
            eval ~close_inputs ~close_outputs ~stdin ~stdout w
    end

module GraphGenerator = Evaluation(GraphBuilder)
(** Used to implement the buffering asp within the interpreter. Reads
    all input from standard in, creates a pipe, then forks.

    The child of the fork replaces standard input with the read end of
    the pipe, then returns to the caller which is expected to evlaute
    a subflow using the buffered data as input.

    The parent of the fork flushes the buffer to the write end of the
    pipe, waits for the child, then exits. *)
let buffer_input () =
    let open Result in
    let input = In_channel.input_all In_channel.stdin in
    let (cin, out) = Typed_descrs.pipe () in
    match Unix.fork () with
    | `In_the_child    -> (Typed_descrs.dup2in cin ;
                           Typed_descrs.close_out out ;
                           Typed_descrs.close_in cin;
                           return ())
    | `In_the_parent p -> (return (Typed_descrs.close_in cin)
                           >>= fun _ -> return (Unix.write (Typed_descrs.out_to_fd out) (Bytes.of_string input))
                           >>= fun _ -> return (Typed_descrs.close_out out)
                           >>= fun _ -> match Unix.waitpid p with
                           | Ok () -> exit 0
                           | Error (`Exit_non_zero n) -> exit n
                           | Error (`Signal sg) -> exit (Signal.to_system_int sg))

module XmlGenerator = struct
    exception Invalid_List of string;;

    (** Inserts an XML section which is composed of:
            <name>
                data
            </name>
        into the out channel **)
    let insert_section out name data fields =
        Xmlm.output out (`El_start (("", name), fields));
        Xmlm.output out (`Data data);
        Xmlm.output out `El_end;
        ()

    (** Calls insert_section in bulk for convience **)
    let rec insert_sections out names data fields =
        match names, data, fields with
        [],[],[] -> ()
        | (_::_),(_::_),[] | (_::_),[],(_::_)
        | [],(_::_),(_::_) | [],[],(_::_) | [],(_::_),[]
        | (_::_),[],[] -> raise (Invalid_List "Lists of uneven size");
        | (n::nr),(d::dr),(f::fr) -> (insert_section out n d f; insert_sections out nr dr fr)

    (** Parses the workflow list for all the the ASP executable names **)
    let rec asps w =
        match w with
        PRIM {cmd;_} -> [cmd]
        | BRNCH (_, {split={cmd = splits;_}; left; right; merge={cmd = merges;_}}) -> let lasps = asps left in
                                                                                      let rasps = asps right in
                                                                                        [splits]@lasps@rasps@[merges]
        | LIN (_, {first;second}) -> let fasps = asps first in
                                     let sasps = asps second in
                                        fasps@sasps
        | AT (_, flow) -> asps flow

    (** the print_*_section family of functions print specific XML sections **)
    let print_asp_section out asp_list =
        Xmlm.output out (`El_start (("", "asps"), []));
        List.iter asp_list (fun e -> insert_section out "asp" e [(("","uuid"), "XXXX")]);
        Xmlm.output out `El_end;
        ()

    let print_copland_section out =
        Xmlm.output out (`El_start (("", "copland"), []));
        insert_section out "phrase" "Insert Copland phrase" [];
        insert_section out "spec" "Determine a measurement specification to use, if applicable" [(("","uuid"), "XXX")];
        Xmlm.output out `El_end;
        ()

    let print_sec_con_section out =
        Xmlm.output out (`El_start (("", "security_context"), []));
        Xmlm.output out (`El_start (("", "selinux"), []));
        insert_section out "type" "Insert selinux type for this APB, if applicable" [];
        Xmlm.output out `El_end;
        Xmlm.output out `El_end;
        ()

    (** Entry point for this module, given a workflow writes an XML file into the buffer **)
    let eval flow =
        let b = Buffer.create 4096 in
            let out = Xmlm.make_output ~indent:(Some 4) (`Buffer b) in
                Xmlm.output out (`Dtd None);
                Xmlm.output out (`El_start (("", "apb"), []));
                let names = ["name";"desc";"uuid";"file";"input_type";"output_type"] in
                let data = ["Insert name";"Insert desc";"Insert uuid";"Insert APB executable file";"Insert input type";"Insert output type"] in
                let fields = [[];[];[];[(("","hash"), "XXXXX")];[];[]] in
                    insert_sections out names data fields;
                let asp_list = asps flow in
                    (** Deduplicate the ASP list before printing the the ASP sections **)
                    print_asp_section out (List.fold asp_list ~init:[] ~f:(fun acc e -> if (List.exists acc (String.equal e)) then acc else (e::acc)));
                print_copland_section out;
                print_sec_con_section out;
                Xmlm.output out `El_end;
        Buffer.contents b
        end

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
let cmd = let open Command.Let_syntax in
    let open Command.Param in
    Command.basic
        ~summary:"Interpret a workflow"
        ~readme:(fun () -> "Read a json representation of a workflow from a file and interprete it.")
        (let%map buffer = flag "-b" no_arg ~doc:"buffer standard input prior to execution"
         and is_sexp    = (flag "-s" no_arg ~doc:"input is sexp format")
         and from_cli   = (flag "-e" no_arg ~doc:"read expression from command line arguments (not a file)")
         and action     = choose_one [flag "-c" (optional (Arg_type.map ~f:(fun s -> `Compile s) string)) ~doc:"compile workflow to C";
                                      flag "-g" (optional (Arg_type.map ~f:(fun s -> `Graphgen s) string)) ~doc:"output workflow as Graphviz DOT file";
                                      flag "-x" (optional (Arg_type.map ~f:(fun s -> `Xmlgen s) string)) ~doc:"output workflow as an APB XML template";
                                      flag "-i" (optional (Arg_type.map ~f:(fun _ -> `Interpret) bool)) ~doc:"interpret expression live (default)"]
                              ~if_nothing_chosen:(Default_to `Interpret)
         and f          = (anon ("workflow.json" %: string)) in
         fun () -> (let open Result in
                    let open Result.Let_syntax in
                    (let%bind _    = (if buffer
                                      then buffer_input ()
                                      else return ()) in
                     let%bind expr = (if from_cli then return f
                                      else try_with (fun _ -> In_channel.read_all f)) in
                     let%bind flow = (if is_sexp
                                      then (try_with (fun _ -> workflow_of_sexp (Sexp.of_string expr)))
                                      else (let%bind json = try_with (fun _ -> Yojson.Safe.from_string expr) in
                                            map_error ~f:(fun e -> Failure e) (workflow_of_yojson json))) in
                     (Printf.fprintf stderr "%s\n" (show_workflow flow);
                      Out_channel.flush stderr;
                      try_with
                          (fun _ ->
                               (match action with
                                | `Interpret      -> Interpreter.eval flow |> fun _ -> ()
                                | `Graphgen gfile -> Out_channel.with_file gfile
                                                         ~f:(fun chan -> GraphGenerator.eval flow
                                                                         |> Out_channel.output_string chan)
                                | `Compile cfile -> Out_channel.with_file cfile
                                                        ~f:(fun chan -> Compiler.eval flow
                                                                        |> Out_channel.output_string chan)
                                | `Xmlgen xmlfile -> Out_channel.with_file xmlfile
                                                        ~f:(fun chan -> XmlGenerator.eval flow
                                                                        |> Out_channel.output_string chan)))
                    ))
                    |> function
                    | Ok _ -> ()
                    | Error e -> (Printf.fprintf stderr "Error: %s\n" (Exn.to_string e) ;
                                  Out_channel.flush stderr)))

let _ = Command.run ~version:"1.0" ~build_info:"RWO" cmd
