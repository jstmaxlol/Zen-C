
#include "typecheck.h"
#include "diagnostics/diagnostics.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ** Internal Helpers **

static void tc_error(TypeChecker *tc, Token t, const char *msg)
{
    zerror_at(t, "%s", msg);
    tc->error_count++;
}

static void tc_error_with_hints(TypeChecker *tc, Token t, const char *msg, const char *const *hints)
{
    zerror_with_hints(t, msg, hints);
    tc->error_count++;
}

static void tc_enter_scope(TypeChecker *tc)
{
    Scope *s = malloc(sizeof(Scope));
    if (!s)
    {
        return;
    }
    s->symbols = NULL;
    s->parent = tc->current_scope;
    tc->current_scope = s;
}

static void tc_exit_scope(TypeChecker *tc)
{
    if (!tc->current_scope)
    {
        return;
    }
    Scope *old = tc->current_scope;
    tc->current_scope = old->parent;

    ZenSymbol *sym = old->symbols;
    while (sym)
    {
        ZenSymbol *next = sym->next;
        free(sym);
        sym = next;
    }
    free(old);
}

static void tc_add_symbol(TypeChecker *tc, const char *name, Type *type, Token t)
{
    ZenSymbol *s = malloc(sizeof(ZenSymbol));
    memset(s, 0, sizeof(ZenSymbol));
    s->name = strdup(name);
    s->type_info = type;
    s->decl_token = t;
    s->next = tc->current_scope->symbols;
    tc->current_scope->symbols = s;
}

static ZenSymbol *tc_lookup(TypeChecker *tc, const char *name)
{
    Scope *s = tc->current_scope;
    while (s)
    {
        ZenSymbol *curr = s->symbols;
        while (curr)
        {
            if (0 == strcmp(curr->name, name))
            {
                return curr;
            }
            curr = curr->next;
        }
        s = s->parent;
    }
    return NULL;
}

// ** Move Semantics Helpers **

static int is_safe_to_copy(TypeChecker *tc, Type *t)
{
    // Use parser's helper if available, or simple heuristic
    return is_type_copy(tc->pctx, t);
}

static void check_use_validity(TypeChecker *tc, ASTNode *var_node, ZenSymbol *sym)
{
    if (!sym || !var_node)
    {
        return;
    }

    if (sym->is_moved)
    {
        char msg[256];
        snprintf(msg, 255, "Use of moved value '%s'", sym->name);

        const char *hints[] = {"This type owns resources and cannot be implicitly copied",
                               "Consider using a reference ('&') to borrow the value instead",
                               NULL};
        tc_error_with_hints(tc, var_node->token, msg, hints);
    }
}

static void mark_symbol_moved(TypeChecker *tc, ZenSymbol *sym, ASTNode *context_node)
{
    (void)context_node;
    if (!sym)
    {
        return;
    }

    // Only move if type is NOT Copy
    Type *t = sym->type_info;
    if (t && !is_safe_to_copy(tc, t))
    {
        sym->is_moved = 1;
    }
}

static void mark_symbol_valid(TypeChecker *tc, ZenSymbol *sym)
{
    (void)tc;
    if (sym)
    {
        sym->is_moved = 0;
    }
}

// ** Node Checkers **

static void check_node(TypeChecker *tc, ASTNode *node);
static int check_type_compatibility(TypeChecker *tc, Type *target, Type *value, Token t);

static void check_expr_binary(TypeChecker *tc, ASTNode *node)
{
    check_node(tc, node->binary.left);
    check_node(tc, node->binary.right);

    Type *left_type = node->binary.left->type_info;
    Type *right_type = node->binary.right->type_info;
    const char *op = node->binary.op;

    // Assignment Logic for Moves (and type compatibility)
    if (strcmp(op, "=") == 0)
    {
        // Check type compatibility for assignment
        if (left_type && right_type)
        {
            check_type_compatibility(tc, left_type, right_type, node->binary.right->token);
        }

        // If RHS is a var, it might Move
        if (node->binary.right->type == NODE_EXPR_VAR)
        {
            ZenSymbol *rhs_sym = tc_lookup(tc, node->binary.right->var_ref.name);
            if (rhs_sym)
            {
                mark_symbol_moved(tc, rhs_sym, node);
            }
        }

        // LHS is being (re-)initialized, so it becomes Valid.
        if (node->binary.left->type == NODE_EXPR_VAR)
        {
            ZenSymbol *lhs_sym = tc_lookup(tc, node->binary.left->var_ref.name);
            if (lhs_sym)
            {
                mark_symbol_valid(tc, lhs_sym);
            }
        }

        // Result type is same as LHS
        node->type_info = left_type;
        return;
    }

    // Arithmetic operators: +, -, *, /, %
    if (strcmp(op, "+") == 0 || strcmp(op, "-") == 0 || strcmp(op, "*") == 0 ||
        strcmp(op, "/") == 0 || strcmp(op, "%") == 0)
    {
        if (left_type && right_type)
        {
            int left_numeric = is_integer_type(left_type) || is_float_type(left_type);
            int right_numeric = is_integer_type(right_type) || is_float_type(right_type);

            if (!left_numeric || !right_numeric)
            {
                char msg[256];
                snprintf(msg, sizeof(msg), "Operator '%s' requires numeric operands", op);
                const char *hints[] = {
                    "Arithmetic operators can only be used with integer or float types", NULL};
                tc_error_with_hints(tc, node->token, msg, hints);
            }
            else
            {
                // Result type: if either is float, result is float; else left type
                if (is_float_type(left_type) || is_float_type(right_type))
                {
                    node->type_info = type_new(TYPE_F64);
                }
                else
                {
                    node->type_info = left_type;
                }
            }
        }
        return;
    }

    // Comparison operators: ==, !=, <, >, <=, >=
    if (strcmp(op, "==") == 0 || strcmp(op, "!=") == 0 || strcmp(op, "<") == 0 ||
        strcmp(op, ">") == 0 || strcmp(op, "<=") == 0 || strcmp(op, ">=") == 0)
    {
        // Result is always bool
        node->type_info = type_new(TYPE_BOOL);

        // Operands should be comparable
        if (left_type && right_type && !type_eq(left_type, right_type))
        {
            // Allow comparison between numeric types
            int left_numeric = is_integer_type(left_type) || is_float_type(left_type);
            int right_numeric = is_integer_type(right_type) || is_float_type(right_type);

            if (!left_numeric || !right_numeric)
            {
                char msg[256];
                snprintf(msg, sizeof(msg), "Cannot compare '%s' with incompatible types", op);
                const char *hints[] = {"Ensure both operands have the same or compatible types",
                                       NULL};
                tc_error_with_hints(tc, node->token, msg, hints);
            }
        }
        return;
    }

    // Logical operators: &&, ||
    if (strcmp(op, "&&") == 0 || strcmp(op, "||") == 0)
    {
        node->type_info = type_new(TYPE_BOOL);
        // Could validate that operands are boolean-like, but C is lax here
        return;
    }

    // Bitwise operators: &, |, ^, <<, >>
    if (strcmp(op, "&") == 0 || strcmp(op, "|") == 0 || strcmp(op, "^") == 0 ||
        strcmp(op, "<<") == 0 || strcmp(op, ">>") == 0)
    {
        if (left_type && right_type)
        {
            if (!is_integer_type(left_type) || !is_integer_type(right_type))
            {
                char msg[256];
                snprintf(msg, sizeof(msg), "Bitwise operator '%s' requires integer operands", op);
                const char *hints[] = {"Bitwise operators only work on integer types", NULL};
                tc_error_with_hints(tc, node->token, msg, hints);
            }
            else
            {
                node->type_info = left_type;
            }
        }
        return;
    }
}

static void check_expr_call(TypeChecker *tc, ASTNode *node)
{
    check_node(tc, node->call.callee);

    const char *func_name = NULL;
    FuncSig *sig = NULL;

    // Check if the function exists (for simple direct calls)
    if (node->call.callee && node->call.callee->type == NODE_EXPR_VAR)
    {
        func_name = node->call.callee->var_ref.name;

        // Look up function signature
        sig = find_func(tc->pctx, func_name);

        if (!sig)
        {
            // Check local scope first, then global symbols
            ZenSymbol *sym = tc_lookup(tc, func_name);
            if (!sym)
            {
                // Check global parser context for functions
                ZenSymbol *global_sym = find_symbol_in_all(tc->pctx, func_name);
                if (!global_sym)
                {
                    error_undefined_function(node->call.callee->token, func_name, NULL);
                    tc->error_count++;
                }
            }
        }
    }

    // Count arguments
    int arg_count = 0;
    ASTNode *arg = node->call.args;
    while (arg)
    {
        arg_count++;
        arg = arg->next;
    }

    // Validate argument count if we have a signature
    if (sig)
    {
        int min_args = sig->total_args;

        // Count required args (those without defaults)
        if (sig->defaults)
        {
            min_args = 0;
            for (int i = 0; i < sig->total_args; i++)
            {
                if (!sig->defaults[i])
                {
                    min_args++;
                }
            }
        }

        if (arg_count < min_args)
        {
            char msg[256];
            snprintf(msg, sizeof(msg), "Too few arguments: '%s' expects at least %d, got %d",
                     func_name, min_args, arg_count);

            const char *hints[] = {"Check the function signature for required parameters", NULL};
            tc_error_with_hints(tc, node->token, msg, hints);
        }
        else if (arg_count > sig->total_args && !sig->is_varargs)
        {
            char msg[256];
            snprintf(msg, sizeof(msg), "Too many arguments: '%s' expects %d, got %d", func_name,
                     sig->total_args, arg_count);

            const char *hints[] = {
                "Remove extra arguments or check if you meant to call a different function", NULL};
            tc_error_with_hints(tc, node->token, msg, hints);
        }
    }

    // Check argument types
    arg = node->call.args;
    int arg_idx = 0;
    while (arg)
    {
        check_node(tc, arg);

        // Validate type against signature
        if (sig && arg_idx < sig->total_args && sig->arg_types && sig->arg_types[arg_idx])
        {
            Type *expected = sig->arg_types[arg_idx];
            Type *actual = arg->type_info;

            if (expected && actual)
            {
                check_type_compatibility(tc, expected, actual, arg->token);
            }
        }

        // If argument is passed by VALUE, and it's a variable, it MOVES.
        if (arg->type == NODE_EXPR_VAR)
        {
            ZenSymbol *sym = tc_lookup(tc, arg->var_ref.name);
            if (sym)
            {
                mark_symbol_moved(tc, sym, node);
            }
        }

        arg = arg->next;
        arg_idx++;
    }
}

static void check_block(TypeChecker *tc, ASTNode *block)
{
    tc_enter_scope(tc);
    ASTNode *stmt = block->block.statements;
    while (stmt)
    {
        check_node(tc, stmt);
        stmt = stmt->next;
    }
    tc_exit_scope(tc);
}

static int check_type_compatibility(TypeChecker *tc, Type *target, Type *value, Token t)
{
    if (!target || !value)
    {
        return 1; // Can't check
    }

    // Simple equality check for now... This will be changed.
    if (!type_eq(target, value))
    {

        // For now we have strict equality on structure.

        // In Zen C (like C), void* is generic.
        if (TYPE_POINTER == target->kind && TYPE_VOID == target->inner->kind)
        {
            return 1;
        }
        if (TYPE_POINTER == value->kind && TYPE_VOID == value->inner->kind)
        {
            return 1;
        }

        // Exception: integer promotion/demotion.

        if (is_integer_type(target) && is_integer_type(value))
        {
            return 1;
        }

        char *t_str = type_to_string(target);
        char *v_str = type_to_string(value);

        char msg[512];
        snprintf(msg, sizeof(msg), "Type mismatch: expected '%s', but found '%s'", t_str, v_str);

        const char *hints[] = {
            "Check if you need an explicit cast",
            "Ensure the types match exactly (no implicit conversions for strict types)", NULL};

        tc_error_with_hints(tc, t, msg, hints);
        free(t_str);
        free(v_str);
        return 0;
    }
    return 1;
}

static void check_var_decl(TypeChecker *tc, ASTNode *node)
{
    if (node->var_decl.init_expr)
    {
        check_node(tc, node->var_decl.init_expr);

        Type *decl_type = node->type_info;
        Type *init_type = node->var_decl.init_expr->type_info;

        if (decl_type && init_type)
        {
            check_type_compatibility(tc, decl_type, init_type, node->token);
        }
        else
        {
            printf("Check skipped for '%s': decl=%p, init=%p\n", node->var_decl.name,
                   (void *)decl_type, (void *)init_type);
        }

        // Move Analysis: If initializing from another variable, it moves.
        if (node->var_decl.init_expr->type == NODE_EXPR_VAR)
        {
            ZenSymbol *init_sym = tc_lookup(tc, node->var_decl.init_expr->var_ref.name);
            if (init_sym)
            {
                mark_symbol_moved(tc, init_sym, node);
            }
        }
    }

    // If type is not explicit, we should ideally infer it from init_expr.
    Type *t = node->type_info;
    if (!t && node->var_decl.init_expr)
    {
        t = node->var_decl.init_expr->type_info;
    }

    tc_add_symbol(tc, node->var_decl.name, t, node->token);
}

static int block_always_returns(ASTNode *block);

static int stmt_always_returns(ASTNode *stmt)
{
    if (!stmt)
    {
        return 0;
    }

    switch (stmt->type)
    {
    case NODE_RETURN:
        return 1;

    case NODE_BLOCK:
        return block_always_returns(stmt);

    case NODE_IF:
        // Both branches must return for if to always return
        if (stmt->if_stmt.then_body && stmt->if_stmt.else_body)
        {
            return stmt_always_returns(stmt->if_stmt.then_body) &&
                   stmt_always_returns(stmt->if_stmt.else_body);
        }
        return 0;

    case NODE_MATCH:
        // TODO: Check all cases return and there's a default
        return 0;

    case NODE_LOOP:
        return 0;

    default:
        return 0;
    }
}

static int block_always_returns(ASTNode *block)
{
    if (!block || block->type != NODE_BLOCK)
    {
        return 0;
    }

    ASTNode *stmt = block->block.statements;
    while (stmt)
    {
        if (stmt_always_returns(stmt))
        {
            return 1;
        }
        stmt = stmt->next;
    }
    return 0;
}

static void check_function(TypeChecker *tc, ASTNode *node)
{
    // Just to suppress the warning.
    (void)tc_error;

    tc->current_func = node;
    tc_enter_scope(tc);

    for (int i = 0; i < node->func.arg_count; i++)
    {
        if (node->func.param_names && node->func.param_names[i])
        {
            tc_add_symbol(tc, node->func.param_names[i], NULL, (Token){0});
        }
    }

    check_node(tc, node->func.body);

    // Control flow analysis: Check if non-void function always returns
    const char *ret_type = node->func.ret_type;
    int is_void = !ret_type || strcmp(ret_type, "void") == 0;

    if (!is_void && node->func.body)
    {
        if (!block_always_returns(node->func.body))
        {
            char msg[256];
            snprintf(msg, sizeof(msg), "Function '%s' may not return a value on all code paths",
                     node->func.name);

            const char *hints[] = {"Ensure all execution paths return a value",
                                   "Consider adding a default return at the end of the function",
                                   NULL};
            tc_error_with_hints(tc, node->token, msg, hints);
        }
    }

    tc_exit_scope(tc);
    tc->current_func = NULL;
}

static void check_expr_var(TypeChecker *tc, ASTNode *node)
{
    ZenSymbol *sym = tc_lookup(tc, node->var_ref.name);

    if (sym && sym->type_info)
    {
        node->type_info = sym->type_info;
    }

    // Check for Use-After-Move
    check_use_validity(tc, node, sym);
}

static void check_node(TypeChecker *tc, ASTNode *node)
{
    if (!node)
    {
        return;
    }

    switch (node->type)
    {
    case NODE_ROOT:
        check_node(tc, node->root.children);
        break;
    case NODE_BLOCK:
        check_block(tc, node);
        break;
    case NODE_VAR_DECL:
        check_var_decl(tc, node);
        break;
    case NODE_FUNCTION:
        check_function(tc, node);
        break;
    case NODE_EXPR_VAR:
        check_expr_var(tc, node);
        break;
    case NODE_RETURN:
        if (node->ret.value)
        {
            check_node(tc, node->ret.value);
        }
        // Check return type compatibility with function
        if (tc->current_func)
        {
            const char *ret_type = tc->current_func->func.ret_type;
            int func_is_void = !ret_type || strcmp(ret_type, "void") == 0;

            if (func_is_void && node->ret.value)
            {
                tc_error(tc, node->token, "Return with value in void function");
            }
            else if (!func_is_void && !node->ret.value)
            {
                char msg[256];
                snprintf(msg, 255, "Return without value in function returning '%s'", ret_type);

                const char *hints[] = {"This function declares a non-void return type",
                                       "Return a value of the expected type", NULL};
                tc_error_with_hints(tc, node->token, msg, hints);
            }
        }
        break;

    // Control flow with nested nodes.
    case NODE_IF:
        check_node(tc, node->if_stmt.condition);
        check_node(tc, node->if_stmt.then_body);
        check_node(tc, node->if_stmt.else_body);
        break;
    case NODE_WHILE:
        check_node(tc, node->while_stmt.condition);
        check_node(tc, node->while_stmt.body);
        break;
    case NODE_FOR:
        tc_enter_scope(tc); // For loop init variable is scoped
        check_node(tc, node->for_stmt.init);
        check_node(tc, node->for_stmt.condition);
        check_node(tc, node->for_stmt.step);
        check_node(tc, node->for_stmt.body);
        tc_exit_scope(tc);
        break;
    case NODE_EXPR_BINARY:
        check_expr_binary(tc, node);
        break;
    case NODE_EXPR_CALL:
        check_expr_call(tc, node);
        break;
    case NODE_EXPR_ARRAY_LITERAL:
        check_node(tc, node->array_literal.elements);
        break;
    default:
        // Generic recursion for lists and other nodes.
        // Special case for Return to trigger move?
        if (node->type == NODE_RETURN && node->ret.value)
        {
            // If returning a variable by value, it is moved.
            if (node->ret.value->type == NODE_EXPR_VAR)
            {
                ZenSymbol *sym = tc_lookup(tc, node->ret.value->var_ref.name);
                if (sym)
                {
                    mark_symbol_moved(tc, sym, node);
                }
            }
        }
        break;
    }

    if (node->next)
    {
        check_node(tc, node->next);
    }
}

// ** Entry Point **

int check_program(ParserContext *ctx, ASTNode *root)
{
    TypeChecker tc = {0};
    tc.pctx = ctx;

    printf("[TypeCheck] Starting semantic analysis...\n");
    check_node(&tc, root);

    if (tc.error_count > 0)
    {
        printf("[TypeCheck] Found %d errors.\n", tc.error_count);
        return 1;
    }
    printf("[TypeCheck] Passed.\n");
    return 0;
}
