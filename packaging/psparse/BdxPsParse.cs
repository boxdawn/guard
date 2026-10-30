// Reads a PowerShell command on stdin and prints what PowerShell's own parser
// sees, as JSON, for boxdawn_guard/powershell_guard.py to judge. It judges
// nothing itself and runs nothing.
//
// Built against the System.Management.Automation.dll of Windows PowerShell
// 5.1, which ships with Windows (packaging/psparse/build.ps1).
//
// A value is either null (known only at run time) or a list of parts: a
// string is literal text, {"var": name} is a variable the Python side may
// resolve from a straight-line assignment.
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management.Automation.Language;
using System.Text;

static class BdxPsParse
{
    static int Main()
    {
        var src = new StreamReader(Console.OpenStandardInput(), new UTF8Encoding(false)).ReadToEnd();
        Token[] tokens;
        ParseError[] errors;
        var ast = Parser.ParseInput(src, out tokens, out errors);

        var o = new StringBuilder();
        o.Append("{\"errors\":").Append(errors.Length);
        o.Append(",\"commands\":[");
        bool first = true;
        foreach (CommandAst c in ast.FindAll(a => a is CommandAst, true))
        {
            if (!first) o.Append(',');
            first = false;
            Command(o, c);
        }
        // Redirections hang on any command, `'x' > f` included.
        o.Append("],\"writes\":[");
        first = true;
        foreach (CommandBaseAst c in ast.FindAll(a => a is CommandBaseAst, true))
        {
            foreach (var r in c.Redirections)
            {
                var f = r as FileRedirectionAst;
                if (f == null) continue;  // 2>&1 and the like write no file
                if (!first) o.Append(',');
                first = false;
                o.Append("{\"start\":").Append(c.Extent.StartOffset)
                 .Append(",\"append\":").Append(f.Append ? "true" : "false")
                 .Append(",\"to\":").Append(Val(f.Location)).Append('}');
            }
        }
        o.Append("],\"assignments\":[");
        first = true;
        foreach (var a in ast.FindAll(a => a is AssignmentStatementAst || a is ForEachStatementAst
                                           || IsIncrement(a), true))
        {
            if (!first) o.Append(',');
            first = false;
            Assignment(o, a, ast);
        }
        o.Append("]}");

        var stdout = new StreamWriter(Console.OpenStandardOutput(), new UTF8Encoding(false));
        stdout.Write(o.ToString());
        stdout.Flush();
        return 0;
    }

    static bool IsIncrement(Ast a)
    {
        var u = a as UnaryExpressionAst;
        return u != null && (u.TokenKind == TokenKind.PlusPlus || u.TokenKind == TokenKind.MinusMinus
                             || u.TokenKind == TokenKind.PostfixPlusPlus || u.TokenKind == TokenKind.PostfixMinusMinus);
    }

    static void Command(StringBuilder o, CommandAst c)
    {
        o.Append("{\"start\":").Append(c.Extent.StartOffset);
        o.Append(",\"name\":").Append(Str(c.GetCommandName()));
        o.Append(",\"op\":").Append(Str(c.InvocationOperator.ToString()));
        o.Append(",\"head\":").Append(Str(c.CommandElements[0].GetType().Name));
        var head = c.CommandElements[0] as ExpressionAst;
        if (head != null && c.GetCommandName() == null) o.Append(",\"head_v\":").Append(Val(head));
        o.Append(",\"elems\":[");
        bool first = true;
        foreach (var e in c.CommandElements.Skip(1))
        {
            if (!first) o.Append(',');
            first = false;
            var p = e as CommandParameterAst;
            if (p != null)
            {
                o.Append("{\"p\":").Append(Str(p.ParameterName)).Append(",\"raw\":").Append(Str(p.Extent.Text));
                if (p.Argument != null) o.Append(",\"a\":").Append(Val(p.Argument));
                o.Append('}');
                continue;
            }
            var arr = e as ArrayLiteralAst;
            if (arr != null)
            {
                o.Append("{\"vs\":[").Append(string.Join(",", arr.Elements.Select(Val))).Append("]}");
                continue;
            }
            var v = e as VariableExpressionAst;
            if (v != null && v.Splatted)
            {
                o.Append("{\"splat\":true}");
                continue;
            }
            o.Append("{\"v\":").Append(Val(e as ExpressionAst)).Append('}');
        }
        o.Append(']');

        var pipe = c.Parent as PipelineAst;
        int index = pipe == null ? 0 : pipe.PipelineElements.IndexOf(c);
        o.Append(",\"pipe_index\":").Append(index);
        if (index > 0)
        {
            var prev = pipe.PipelineElements[index - 1] as CommandExpressionAst;
            bool text = prev != null && (prev.Expression is StringConstantExpressionAst
                                         || prev.Expression is ExpandableStringExpressionAst);
            o.Append(",\"pipe_from_text\":").Append(text ? Val(prev.Expression) : "false");
        }
        o.Append('}');
    }

    static void Assignment(StringBuilder o, Ast a, ScriptBlockAst root)
    {
        string name = null, op = "Equals", value = "null";
        bool top = false;
        var s = a as AssignmentStatementAst;
        if (s != null)
        {
            var left = s.Left as VariableExpressionAst;
            name = left == null ? null : left.VariablePath.UserPath;
            op = s.Operator.ToString();
            var named = s.Parent as NamedBlockAst;
            top = named != null && named.Parent == root;
            var right = s.Right as CommandExpressionAst;
            if (right != null) value = Val(right.Expression);
        }
        var f = a as ForEachStatementAst;
        if (f != null) { name = f.Variable.VariablePath.UserPath; op = "ForEach"; }
        var u = a as UnaryExpressionAst;
        if (u != null)
        {
            var v = u.Child as VariableExpressionAst;
            name = v == null ? null : v.VariablePath.UserPath;
            op = "Increment";
        }
        o.Append("{\"var\":").Append(Str(name)).Append(",\"op\":").Append(Str(op))
         .Append(",\"top\":").Append(top ? "true" : "false")
         .Append(",\"pos\":").Append(a.Extent.StartOffset)
         .Append(",\"value\":").Append(value).Append('}');
    }

    static string Val(ExpressionAst e)
    {
        var s = e as StringConstantExpressionAst;
        if (s != null) return "[" + Str(s.Value) + "]";
        var v = e as VariableExpressionAst;
        if (v != null) return v.Splatted ? "null" : "[{\"var\":" + Str(v.VariablePath.UserPath) + "}]";
        var x = e as ExpandableStringExpressionAst;
        if (x != null) return Expandable(x);
        return "null";
    }

    // "$dir\file" -> ["", {"var":"dir"}, "\file"]. Only the plain forms: a
    // backtick escape, a doubled quote, a here-string or `$(...)` is null.
    static string Expandable(ExpandableStringExpressionAst x)
    {
        if (x.NestedExpressions.Count == 0) return "[" + Str(x.Value) + "]";
        string text = x.Extent.Text;
        int skip;
        if (x.StringConstantType == StringConstantType.DoubleQuoted) skip = 1;
        else if (x.StringConstantType == StringConstantType.BareWord) skip = 0;
        else return "null";
        string inner = text.Substring(skip, text.Length - 2 * skip);
        if (inner.IndexOf('`') >= 0 || inner.IndexOf("\"\"") >= 0) return "null";
        int baseOffset = x.Extent.StartOffset + skip, at = 0;
        var parts = new List<string>();
        foreach (var n in x.NestedExpressions.OrderBy(n => n.Extent.StartOffset))
        {
            var v = n as VariableExpressionAst;
            if (v == null) return "null";
            int start = n.Extent.StartOffset - baseOffset;
            parts.Add(Str(inner.Substring(at, start - at)));
            parts.Add("{\"var\":" + Str(v.VariablePath.UserPath) + "}");
            at = n.Extent.EndOffset - baseOffset;
        }
        parts.Add(Str(inner.Substring(at)));
        return "[" + string.Join(",", parts) + "]";
    }

    static string Str(string s)
    {
        if (s == null) return "null";
        var b = new StringBuilder("\"");
        foreach (char ch in s)
        {
            switch (ch)
            {
                case '"': b.Append("\\\""); break;
                case '\\': b.Append("\\\\"); break;
                case '\n': b.Append("\\n"); break;
                case '\r': b.Append("\\r"); break;
                case '\t': b.Append("\\t"); break;
                default:
                    if (ch < 0x20) b.Append("\\u").Append(((int)ch).ToString("x4"));
                    else b.Append(ch);
                    break;
            }
        }
        return b.Append('"').ToString();
    }
}
