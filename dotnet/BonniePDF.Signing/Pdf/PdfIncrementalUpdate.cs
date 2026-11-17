using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace BonniePDF.Signing.Pdf;

/// <summary>
/// Minimal PDF reading + incremental-update construction for signing
/// BonniePDF-generated output. Faithful port of the TypeScript <c>pdf.ts</c>.
///
/// This is NOT a general PDF parser: it understands only the classic
/// cross-reference / <c>trailer</c> structure BonniePDF emits. Pointing it at
/// arbitrary third-party PDFs (xref streams, object streams) is out of scope.
/// </summary>
internal static class PdfIncrementalUpdate
{
    private const string Asterisks = "**********"; // offsets up to ~10 GB
    public static readonly string ByteRangePlaceholder = $"[0 {Asterisks} {Asterisks} {Asterisks}]";

    /// <summary>Hex characters reserved for the CMS envelope (16384 hex = 8 KB binary).</summary>
    public const int SignatureHexLength = 16384;

    public static string Latin1Decode(byte[] bytes) => Encoding.Latin1.GetString(bytes);

    public static byte[] Latin1Encode(string text) => Encoding.Latin1.GetBytes(text);

    /// <summary>Find the byte offset of an ASCII needle, or -1.</summary>
    public static int IndexOfAscii(byte[] haystack, string needle, int from = 0)
    {
        for (int i = from; i <= haystack.Length - needle.Length; i++)
        {
            bool match = true;
            for (int j = 0; j < needle.Length; j++)
            {
                if (haystack[i + j] != (byte)needle[j]) { match = false; break; }
            }
            if (match) return i;
        }
        return -1;
    }

    private static string EscapeLiteral(string text) =>
        text.Replace("\\", "\\\\").Replace("(", "\\(").Replace(")", "\\)").Replace("\r", "\\r").Replace("\n", "\\n");

    /// <summary>Render a value as a PDF text string: literal for ASCII, UTF-16BE hex otherwise.</summary>
    public static string PdfTextString(string text)
    {
        bool ascii = text.All(c => c >= 0x20 && c <= 0x7e);
        if (ascii) return $"({EscapeLiteral(text)})";
        var hex = new StringBuilder("FEFF");
        foreach (char c in text) hex.Append(((int)c).ToString("X4", CultureInfo.InvariantCulture));
        return $"<{hex}>";
    }

    /// <summary>Format a date as a PDF date string <c>D:YYYYMMDDHHmmSS+00'00'</c> (UTC).</summary>
    public static string PdfDate(DateTimeOffset date)
    {
        var u = date.ToUniversalTime();
        return $"D:{u:yyyyMMddHHmmss}+00'00'";
    }

    public sealed class PdfInfo
    {
        public int RootId;
        public string CatalogBody;
        public int TargetPageId;
        public string TargetPageBody;
        public List<int> PageIds;
        public int Size;
        public string IdArray;
        public long PrevStartxref;
    }

    public sealed class SignatureDictMeta
    {
        public string Reason;
        public string Location;
        public string ContactInfo;
        public string Name;
        public DateTimeOffset SigningTime;
        public string SubFilter = "adbe.pkcs7.detached";
    }

    public sealed class VisibleSignature
    {
        public double[] Rect;          // [x, y, width, height]
        public string ContentStream;
    }

    private static string ReadObjectDict(string text, int id)
    {
        var marker = new Regex($"(?:^|[^0-9]){id} 0 obj");
        var m = marker.Match(text);
        if (!m.Success) throw new InvalidOperationException($"object {id} not found");
        int objStart = m.Index + m.Length;
        int dictStart = text.IndexOf("<<", objStart, StringComparison.Ordinal);
        if (dictStart < 0) throw new InvalidOperationException($"object {id}: no dictionary");
        int depth = 0;
        int i = dictStart;
        for (; i < text.Length; i++)
        {
            if (text[i] == '<' && i + 1 < text.Length && text[i + 1] == '<') { depth++; i++; }
            else if (text[i] == '>' && i + 1 < text.Length && text[i + 1] == '>') { depth--; i++; if (depth == 0) break; }
        }
        return text.Substring(dictStart + 2, i - 1 - (dictStart + 2));
    }

    private static int ReadRef(string dictBody, string key)
    {
        var m = new Regex($@"{Regex.Escape(key)}\s*\[?\s*(\d+)\s+0\s+R").Match(dictBody);
        if (!m.Success) throw new InvalidOperationException($"reference {key} not found");
        return int.Parse(m.Groups[1].Value, CultureInfo.InvariantCulture);
    }

    private static List<int> ReadKids(string pagesBody)
    {
        var m = new Regex(@"/Kids\s*\[([^\]]*)\]").Match(pagesBody);
        if (!m.Success) throw new InvalidOperationException("reference /Kids not found");
        return Regex.Matches(m.Groups[1].Value, @"(\d+)\s+0\s+R")
            .Select(x => int.Parse(x.Groups[1].Value, CultureInfo.InvariantCulture)).ToList();
    }

    /// <summary>Parse the structural facts needed to append a signature.</summary>
    public static PdfInfo ParsePdf(byte[] bytes, int pageIndex = 0)
    {
        string text = Latin1Decode(bytes);

        int lastStartxref = text.LastIndexOf("startxref", StringComparison.Ordinal);
        if (lastStartxref < 0) throw new InvalidOperationException("not a classic-xref PDF: no startxref");
        long prevStartxref = long.Parse(
            new Regex(@"startxref\s+(\d+)").Match(text.Substring(lastStartxref)).Groups[1].Value,
            CultureInfo.InvariantCulture);

        int trailerStart = text.LastIndexOf("trailer", StringComparison.Ordinal);
        if (trailerStart < 0) throw new InvalidOperationException("not a classic-xref PDF: no trailer");
        string trailer = text.Substring(trailerStart);
        int rootId = ReadRef(trailer, "/Root");
        int size = int.Parse(new Regex(@"/Size\s+(\d+)").Match(trailer).Groups[1].Value, CultureInfo.InvariantCulture);
        var idMatch = new Regex(@"/ID\s*(\[[^\]]*\])").Match(trailer);

        string catalogBody = ReadObjectDict(text, rootId);
        int pagesId = ReadRef(catalogBody, "/Pages");
        string pagesBody = ReadObjectDict(text, pagesId);
        var pageIds = ReadKids(pagesBody);
        int targetIndex = Math.Max(0, Math.Min(pageIndex, pageIds.Count - 1));
        int targetPageId = pageIds[targetIndex];
        string targetPageBody = ReadObjectDict(text, targetPageId);

        return new PdfInfo
        {
            RootId = rootId,
            CatalogBody = catalogBody,
            TargetPageId = targetPageId,
            TargetPageBody = targetPageBody,
            PageIds = pageIds,
            Size = size - 1,
            IdArray = idMatch.Success ? idMatch.Groups[1].Value : null,
            PrevStartxref = prevStartxref,
        };
    }

    /// <summary>
    /// Append a signature revision (sig value, field/widget, AcroForm, plus
    /// overridden catalog and target page, and optional appearance objects) and
    /// a new classic xref section. The returned bytes still carry the
    /// <c>/ByteRange</c> and <c>/Contents</c> placeholders.
    /// </summary>
    public static byte[] BuildIncrementalUpdate(byte[] original, PdfInfo info, SignatureDictMeta meta, VisibleSignature visible)
    {
        int nextId = info.Size;
        int sigId = ++nextId;
        int widgetId = ++nextId;
        int acroFormId = ++nextId;
        int apId = visible != null ? ++nextId : 0;
        int fontId = visible != null ? ++nextId : 0;
        int newSize = nextId + 1;

        string sigDict = BuildSigDict(meta);

        string rect = visible != null
            ? "[" + string.Join(" ", visible.Rect.Select(n => n.ToString(CultureInfo.InvariantCulture))) + "]"
            : "[0 0 0 0]";
        string widgetDict =
            "<<\n  /Type /Annot\n  /Subtype /Widget\n  /FT /Sig\n  /Rect " + rect + "\n" +
            $"  /V {sigId} 0 R\n  /T (Signature1)\n  /F 132\n  /P {info.TargetPageId} 0 R\n";
        if (visible != null) widgetDict += $"  /AP << /N {apId} 0 R >>\n";
        widgetDict += ">>";

        string acroFormDict = $"<<\n  /Fields [{widgetId} 0 R]\n  /SigFlags 3\n>>";
        string catalogDict = "<<" + InjectKey(info.CatalogBody, $"  /AcroForm {acroFormId} 0 R\n") + ">>";
        string pageDict = "<<" + InjectAnnot(info.TargetPageBody, widgetId) + ">>";

        var offsets = new Dictionary<int, long>();
        var appended = new StringBuilder();
        long startBase = original.Length;

        void WriteObj(int id, string body)
        {
            offsets[id] = startBase + appended.Length;
            appended.Append($"{id} 0 obj\n{body}\nendobj\n");
        }

        // Original ends in `%%EOF` with no trailing newline; separate cleanly.
        appended.Append('\n');
        WriteObj(sigId, sigDict);
        WriteObj(widgetId, widgetDict);
        WriteObj(acroFormId, acroFormDict);
        if (visible != null)
        {
            double w = visible.Rect[2];
            double h = visible.Rect[3];
            string content = visible.ContentStream;
            int length = Latin1Encode(content).Length;
            WriteObj(apId,
                $"<< /Type /XObject /Subtype /Form /FormType 1 /BBox [0 0 {w.ToString(CultureInfo.InvariantCulture)} {h.ToString(CultureInfo.InvariantCulture)}]" +
                $" /Resources << /Font << /Helv {fontId} 0 R >> >> /Length {length} >>\n" +
                $"stream\n{content}\nendstream");
            WriteObj(fontId, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>");
        }
        WriteObj(info.RootId, catalogDict);
        WriteObj(info.TargetPageId, pageDict);

        long xrefOffset = startBase + appended.Length;
        appended.Append(BuildXref(offsets));

        var trailerParts = new List<string> { $"/Size {newSize}", $"/Root {info.RootId} 0 R", $"/Prev {info.PrevStartxref}" };
        if (!string.IsNullOrEmpty(info.IdArray)) trailerParts.Add($"/ID {info.IdArray}");
        appended.Append($"trailer\n<< {string.Join(" ", trailerParts)} >>\nstartxref\n{xrefOffset}\n%%EOF");

        byte[] appendedBytes = Latin1Encode(appended.ToString());
        var outBytes = new byte[original.Length + appendedBytes.Length];
        Buffer.BlockCopy(original, 0, outBytes, 0, original.Length);
        Buffer.BlockCopy(appendedBytes, 0, outBytes, original.Length, appendedBytes.Length);
        return outBytes;
    }

    private static string BuildSigDict(SignatureDictMeta meta)
    {
        var lines = new List<string>
        {
            "<<",
            "  /Type /Sig",
            "  /Filter /Adobe.PPKLite",
            $"  /SubFilter /{meta.SubFilter}",
            $"  /ByteRange {ByteRangePlaceholder}",
            $"  /Contents <{new string('0', SignatureHexLength)}>",
        };
        if (!string.IsNullOrEmpty(meta.Reason)) lines.Add($"  /Reason {PdfTextString(meta.Reason)}");
        if (!string.IsNullOrEmpty(meta.Location)) lines.Add($"  /Location {PdfTextString(meta.Location)}");
        if (!string.IsNullOrEmpty(meta.ContactInfo)) lines.Add($"  /ContactInfo {PdfTextString(meta.ContactInfo)}");
        if (!string.IsNullOrEmpty(meta.Name)) lines.Add($"  /Name {PdfTextString(meta.Name)}");
        lines.Add($"  /M ({PdfDate(meta.SigningTime)})");
        lines.Add(">>");
        return string.Join("\n", lines);
    }

    private static string InjectKey(string dictBody, string keyLine) =>
        "\n" + keyLine + Regex.Replace(dictBody, "^\n", string.Empty);

    private static string InjectAnnot(string pageBody, int widgetId)
    {
        string refStr = $"{widgetId} 0 R";
        if (new Regex(@"/Annots\s*\[").IsMatch(pageBody))
        {
            string merged = new Regex(@"(/Annots\s*\[)([^\]]*)\]").Replace(
                pageBody, m => $"{m.Groups[1].Value}{m.Groups[2].Value.Trim()} {refStr}]", 1);
            return "\n" + Regex.Replace(merged, "^\n", string.Empty);
        }
        return InjectKey(pageBody, $"  /Annots [{refStr}]\n");
    }

    private static string BuildXref(Dictionary<int, long> offsets)
    {
        var ids = offsets.Keys.Order().ToList();
        var groups = new List<List<int>>();
        foreach (int id in ids)
        {
            var last = groups.Count > 0 ? groups[^1] : null;
            if (last != null && id == last[^1] + 1) last.Add(id);
            else groups.Add(new List<int> { id });
        }
        var xref = new StringBuilder("xref\n");
        foreach (var group in groups)
        {
            xref.Append($"{group[0]} {group.Count}\n");
            foreach (int id in group)
            {
                xref.Append($"{offsets[id].ToString(CultureInfo.InvariantCulture).PadLeft(10, '0')} 00000 n \n");
            }
        }
        return xref.ToString();
    }

    [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Auto)]
    public readonly struct ByteRangeResult
    {
        public readonly byte[] Signed;
        public readonly int ContentsStart;
        public readonly int ContentsEnd;
        public ByteRangeResult(byte[] signed, int start, int end) { Signed = signed; ContentsStart = start; ContentsEnd = end; }
    }

    /// <summary>
    /// Back-patch the <c>/ByteRange</c> placeholder with real offsets and return
    /// the signed byte span (everything except the <c>/Contents</c> hex string).
    /// </summary>
    public static ByteRangeResult PatchByteRange(byte[] bytes)
    {
        int brIndex = IndexOfAscii(bytes, ByteRangePlaceholder);
        if (brIndex < 0) throw new InvalidOperationException("byte-range placeholder not found");

        int contentsTag = IndexOfAscii(bytes, "/Contents <", brIndex);
        int open = IndexOfAscii(bytes, "<", contentsTag);
        int close = IndexOfAscii(bytes, ">", open);
        int contentsStart = open;
        int contentsEnd = close + 1;

        long len2 = bytes.Length - contentsEnd;
        string replacement = $"[0 {contentsStart} {contentsEnd} {len2}";
        int padTo = ByteRangePlaceholder.Length;
        replacement = replacement + new string(' ', padTo - replacement.Length - 1) + "]";
        if (replacement.Length != padTo) throw new InvalidOperationException("byte range too large for placeholder");
        for (int i = 0; i < replacement.Length; i++) bytes[brIndex + i] = (byte)replacement[i];

        var signed = new byte[contentsStart + (bytes.Length - contentsEnd)];
        Buffer.BlockCopy(bytes, 0, signed, 0, contentsStart);
        Buffer.BlockCopy(bytes, contentsEnd, signed, contentsStart, bytes.Length - contentsEnd);
        return new ByteRangeResult(signed, contentsStart, contentsEnd);
    }

    /// <summary>Write the hex-encoded CMS envelope into the <c>/Contents</c> placeholder.</summary>
    public static void InjectContents(byte[] bytes, int contentsStart, int contentsEnd, byte[] cms)
    {
        int capacity = contentsEnd - contentsStart - 2; // exclude '<' and '>'
        if (cms.Length * 2 > capacity)
        {
            throw new InvalidOperationException(
                $"CMS envelope ({cms.Length} bytes) exceeds /Contents capacity ({capacity / 2} bytes)");
        }
        int pos = contentsStart + 1;
        foreach (byte b in cms)
        {
            bytes[pos++] = HexCharCode((b >> 4) & 0xf);
            bytes[pos++] = HexCharCode(b & 0xf);
        }
    }

    private static byte HexCharCode(int nibble) => (byte)(nibble < 10 ? '0' + nibble : 'A' + (nibble - 10));
}
