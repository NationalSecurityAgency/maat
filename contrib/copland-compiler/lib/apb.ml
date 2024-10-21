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
open Ccode
open State
open Core
open Asp

(** Generate code to open a fresh pipe with identifier based on the
    given string.

    Defines a new local variable for the pipe, adds body
    statements to open the pipe and check for error, and adds cleanups
    to close the pipe if an error occurs later.

    Returns the pair of expression {i(read end, write end)} for later
    use. *)
let make_pipe_pf pipename =
    let%bind pipeident = fresh_ident pipename in
    let%bind _         = append_comment @@ Printf.sprintf "initializing pipe %s" pipeident in
    let%bind outlabel  = fresh_ident ("out_"^pipename) in
    let%bind rcvar     = get_rcvar in
    let%bind _         = append_local ("int", pipeident, Some 2) in
    let%bind cleanup   = goto_next_cleanup in
    let%bind _         = append_statement (Seq (Assign (Var rcvar, CallExpr ("pipe", [Var pipeident])),
                                                If (BinExpr (Neq, Var rcvar, IntLit 0),
                                                    Seq (Expr (CallExpr ("dlog", [IntLit 0;
                                                                                StringLit "Failed to create pipe: %s\n";
                                                                                CallExpr ("strerror", [Var "errno"])])),
                                                        cleanup),
                                                    None
                                                )
                                            )
                                        ) in
    let%map _         = prepend_cleanup outlabel 
                                            (Seq (Expr (CallExpr ("close", [Subscript (Var pipeident, IntLit 0)])),
                                                Expr (CallExpr ("close", [Subscript (Var pipeident, IntLit 1)])))) in
    (pipe_read_end_expr pipeident, pipe_write_end_expr pipeident)


(** Transforms special asp argument expression, graph, into 
corresponding asp_measure function arguement *)
let handle_special_arg (target : expr) : (pfunc, expr option, pfunc) t =
    let%bind graphpathvar = get_graphpathvar in
    return @@
    match target with
    | StringLit "graph" ->  Some (Var graphpathvar)
    (*TODO: implement peerchan, resultschan*)
    | _       ->  None


(** Generate code to find a specific ASP in a set of ASPs

    Defines a new local variable which holds the reference to the ASP,
    adds body statement in the case of an error, and a label to jump to
    if an error occurs.

    Returns the identifier for the ASP *)
let find_asp asp =
    let%bind _        = append_comment @@ sprintf "Finding asp with name %s" asp in
    let%bind rcvar    = get_rcvar in
    let%bind varident = fresh_ident (asp^"_asp") in
    let%bind outlabel = fresh_ident ("find_"^asp^"_error") in
    let%bind _        = append_local ("struct asp", "*"^varident, None) in
    let%bind _        = append_statement 
                        (Assign (Var varident, 
                        CallExpr ("find_asp", [BinExpr (Deref, Var "apb", Var "asps"); StringLit asp]))) in
    let%bind cleanup  = goto_next_cleanup in
    let%bind _        = append_if
                                (BinExpr (Eq, Var varident, EnumLit "NULL"))
                                [
                                Expr (CallExpr ("dlog", [IntLit 0;StringLit "Failed to find ASP: %s\n"; BinExpr (Deref, Var varident, Var "name")]));
                                Assign (Var rcvar, IntLit 1);
                                cleanup
                                ]
                                None in
    let%bind _         = prepend_cleanup outlabel Skip in
    return @@ Var varident

(** Generates code that produces an expression containing the node id of 
a file argument to an asp. 
If the file does not already have a corresponding node in the measurement with the 
corresponding target type, the code will initialize one. *)
let get_node_id_str (asp : asp_t) (arg : expr) : (pfunc, expr, pfunc) t =
    let%bind _       = append_comment @@ sprintf "getting node id of arg: %s" (c_of_expr arg) in
    let%bind pathvar = fresh_ident "pathvar" in
    let%bind _       = append_local ("measurement_variable *", pathvar, None) in
    let%bind addr    = fresh_ident "addr" in
    let%bind _       = append_local("address *", addr, None) in
    let%bind _       = append_statement 
                        (Assign(Var addr,(CallExpr("alloc_address", [UnExpr(AddrOf, (Var asp.address_type))])))) in
    let%bind _       = append_statement
                            (Assign (Var pathvar, 
                                CallExpr("new_measurement_variable",
                                    [
                                        UnExpr(AddrOf, Var (asp.target_type));
                                        Var addr
                                    ]
                                ))) in
    let filepath_lhs = BinExpr(Deref, Cast("file_addr *", BinExpr(Deref, Var pathvar, Var "address")), Var "fullpath_file_name") in
    let%bind _       = append_statement (Assign(filepath_lhs, CallExpr("strdup", [arg]))) in 
    let%bind node_id = fresh_ident "node_id" in
    let%bind nid_str = fresh_ident "node_id_str" in
    let%bind _       = append_local("node_id_t", node_id, None) in 
    let%bind _       = append_local("node_id_str", nid_str, None) in
    let%bind gvar    = get_graphvar in
    let%bind nodeset = get_node_hashset in
    let%bind _       = append_statement(Assign(Var node_id, 
                            CallExpr("measurement_graph_get_node", [Var gvar; Var pathvar] ))) in
    let%bind (_,stmt) = stmt_of_comp_scope @@
        let%bind _             =  append_statement(Expr (CallExpr("measurement_graph_add_node", [Var gvar; Var pathvar; EnumLit "NULL"; UnExpr(AddrOf, Var node_id)]))) in
        let%bind node_id_ptr   = fresh_ident "node_id_ptr" in
        let%bind _             = append_local("node_id_t *", node_id_ptr, None) in
        let%bind _             = append_statement(Assign(Var node_id_ptr, CallExpr("malloc", [CallExpr("sizeof", [EnumLit "node_id_t"])]))) in
        let%bind _             = append_statement(Assign(UnExpr(PointsTo, Var node_id_ptr), Var node_id)) in
        let%bind _             = append_statement(Expr(CallExpr("g_hash_table_add", [Var nodeset; Var node_id_ptr]))) in
        return () in
    let%bind _       = append_if 
                        (BinExpr(Eq, Var node_id, EnumLit "INVALID_NODE_ID"))
                        ([stmt])
                        None in
    let%bind _      = append_statement (Expr (CallExpr("str_of_node_id", [Var node_id; Var nid_str]))) in
    return @@ Var nid_str


(** Generates code to call the {i fork()} builtin.

    Defines new local variables for the pid of the child, adds the call and
    error handling, and adds a cleanup to kill the child.

    Returns the expression {i child pid}. *)
let make_fork = 
    let%bind pidident = fresh_ident "fork_pid" in
    let%bind outlabel = fresh_ident "out_runbuffer" in
    let%bind rcvar    = get_rcvar in
    let%bind cleanup  = goto_next_cleanup in
    let%bind _        = append_local ("pid_t", pidident, None) in
    let%bind _        = append_statement (Assign (Var pidident, CallExpr ("fork", []))) in
    let%bind _        = append_statement (Assign (Var rcvar, Var pidident)) in
    let%bind _        = append_if (BinExpr (Lt, Var rcvar, IntLit 0))
                                    [
                                        Expr (CallExpr ("dlog", [IntLit 0; 
                                        StringLit "Failed to fork buffering process: %s\n";
                                        CallExpr ("strerror", [Var "errno"])]));
                                        cleanup
                                    ] 
                                None in
    let%bind _        = prepend_cleanup outlabel
                                            (Expr (CallExpr ("close", [Var pidident]))) in
    return @@ Var pidident

(** Generate a call to {i waitpid} for the given PID expression.

    Adds a local variable for the child status, appends the {i
    waitpid} call and discards the return value.

    Returns the expression for the child status variable. *)
let make_waitpid_pf pidexpr =
let%bind statusvar = fresh_ident "status" in
let%bind _         = append_local ("int", statusvar, None) in
let%bind _         = append_statement (Expr (CallExpr ("waitpid", [pidexpr;
                                                                    UnExpr (AddrOf, Var statusvar);
                                                                    IntLit 0]))) in
let%bind cleanup   = goto_next_cleanup in
let%bind _         = append_if 
                            (BinExpr (Lt, (Var statusvar), (IntLit 0)))
                            [cleanup]
                            None in
let%bind rcvar     = get_rcvar in
let%bind _         = append_statement (Assign(Var rcvar, Var statusvar)) in
return @@ Var statusvar

(** Initializes measurement graph 
    Returns variables representing the measurement graph pointer
    and a pointer to the path pointing to the measurement graph *)
let init_meas_graph =
    let%bind _        = append_comment "initializing measurement graph" in
    let%bind graphvar = get_graphvar in
    let%bind graph_path_var = get_graphpathvar in
    let%bind _ = append_local("measurement_graph *", graphvar, None) in
    let%bind _ = append_local("char *", graph_path_var, None) in
    let%bind _ = append_statement 
        (Assign (Var graphvar, 
            CallExpr("create_measurement_graph", [EnumLit "NULL"]))) in
    let%bind _ = append_statement
        (Assign (Var graph_path_var,
            CallExpr("measurement_graph_get_path", [Var graphvar]))) in
    return @@ (Var graphvar, Var graph_path_var)



(** Generates code to call a function that implements signing and sending the current measurment graph *)
let sign_meas : (Ccode.pfunc, expr, Ccode.pfunc) State.t =
    let%bind graphvar = get_graphvar in
    let%bind apb_asps     = fresh_ident "apb_apbs" in 
    let%bind _            = append_local ("GList *", apb_asps, None) in
    let%bind _            = append_statement (Assign(Var apb_asps, BinExpr (Deref, Var "apb", Var "asps"))) in
    let%bind ret_val      = fresh_ident "ret_val" in
    let%bind _            = append_local ("int", ret_val, None) in
    let%bind _            = append_statement (Expr(CallExpr("execute_updated_sign_send_pipeline", [Var graphvar; Var "scen"; Var "peerchan"; Var apb_asps ]))) in
    return @@ Var ret_val




(** Generates code to execute a statement asynchronously in a forked child process. 
    Returns the process id of the child process *)
let async_run_stmt (stmt : statement) =
    let%bind rcvar                   = get_rcvar in
    let%bind childpid                = make_fork in
    let%bind _                       = append_if (BinExpr(Eq, Var rcvar, IntLit 0))
                                            [stmt] None in
    return childpid

(** Takes a computation that generates code, 
    uses it to create a statement containing the body of the code,
    and runs it asynchronously.
    
    Returns the process id of the child process. *)
let async_run (c : (Ccode.pfunc, 'a, Ccode.pfunc) State.t) =
    let%bind (_, stmt) = stmt_of_comp c in
    let%bind childpid  = async_run_stmt stmt  in
    return childpid 

(** Takes a computation that generates code and returns an expression (possibly
    limitted by the scope of the computation), uses it to create a statement
    containing the body of the code, appends a command to assign the result
    expression to a variable declared in the outer scope, and runs it
    asynchronously. Returns the process id of the child process and the variable
    that stores the result. Note that the variable will not actually hold the
    intended computation until after the child process has terminated. *)
let async_run_ret (ret_type : ident) (c : (Ccode.pfunc, expr option, Ccode.pfunc) State.t) :
    (pfunc, expr * expr option, pfunc) State.t =
    let%bind (o, stmt)       = stmt_of_comp c in
    match o with
    | Some e ->
        let%bind async_ret_pipe  = fresh_ident "async_ret_pipe" in
        let%bind _               = make_pipe_pf async_ret_pipe in 
        let%bind async_return    = fresh_ident "async_return" in
        let%bind _               = append_local (ret_type, async_return, None) in
        let%bind childpid        = async_run_stmt @@ Seq(stmt, Assign(Var async_return, e)) in
        return (childpid, Some (Var async_return))
    | None ->
        let%bind childpid        = async_run_stmt stmt in
        return (childpid, None)
    


let standard_apb_includes = [
    "<stdio.h>";
    "<sys/types.h>";
    "<sys/wait.h>";
    "<sys/file.h>";
    "<unistd.h>";
    "<fcntl.h>";
    "<errno.h>";
    "<string.h>";
    "<signal.h>";
    "<common/apb_info.h>";
    "<maat-basetypes.h>";
    "<util/util.h>";
    "<common/asp.h>";
    "<maat-envvars.h>";
    "<apb/apb.h>";
    "\"apb-common.h\"\n";
    "<graph/graph-core.h>";
    "<glib/gqueue.h>";
    "<glib/glist.h>";
    "<glib/ghash.h>";
    "\"userspace_appraiser_common_funcs.h\"";
    "<semaphore.h>";
]
    
(** Convert the {!type:pfunc} to a self contained compilable C
file and return it as a string. Includes generation of necessary {i #include} directives for
functions used by the generators in this module, and {i extern}
declarations for the quasi-builtins. *)
let c_of_pfunc pf =
    let c : cfile = {
        globals = [];
        includes = standard_apb_includes;
        funcs = [pf];
    } in
    cfile_to_string c