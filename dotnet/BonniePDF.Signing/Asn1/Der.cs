using System;
using System.Collections.Generic;
using System.Globalization;
using System.Runtime.InteropServices;

namespace BonniePDF.Signing.Asn1;

/// <summary>
/// Minimal ASN.1 DER writer + reader, mirroring the TypeScript <c>asn1/der.ts</c>.
/// Used to build the RFC 3161 TimeStampReq and to extract the TimeStampToken
/// from the response without depending on a specific BCL API surface.
/// </summary>
internal static class Der
{
    public static byte[] Length(int length)
    {
        if (length < 0x80) return new[] { (byte)length };
        var bytes = new List<byte>();
        int n = length;
        while (n > 0) { bytes.Insert(0, (byte)(n & 0xff)); n >>= 8; }
        bytes.Insert(0, (byte)(0x80 | bytes.Count));
        return bytes.ToArray();
    }

    public static byte[] Tlv(byte tag, byte[] value)
    {
        byte[] len = Length(value.Length);
        var result = new byte[1 + len.Length + value.Length];
        result[0] = tag;
        Buffer.BlockCopy(len, 0, result, 1, len.Length);
        Buffer.BlockCopy(value, 0, result, 1 + len.Length, value.Length);
        return result;
    }

    public static byte[] Concat(params byte[][] parts)
    {
        int total = 0;
        foreach (byte[] p in parts) total += p.Length;
        var outp = new byte[total];
        int offset = 0;
        foreach (byte[] p in parts) { Buffer.BlockCopy(p, 0, outp, offset, p.Length); offset += p.Length; }
        return outp;
    }

    public static byte[] Sequence(params byte[][] children) => Tlv(0x30, Concat(children));

    public static byte[] Oid(string dotted)
    {
        string[] parts = dotted.Split('.');
        var body = new List<byte> { (byte)(40 * int.Parse(parts[0], CultureInfo.InvariantCulture) + int.Parse(parts[1], CultureInfo.InvariantCulture)) };
        for (int i = 2; i < parts.Length; i++)
        {
            int value = int.Parse(parts[i], CultureInfo.InvariantCulture);
            var stack = new List<byte> { (byte)(value & 0x7f) };
            value >>= 7;
            while (value > 0) { stack.Insert(0, (byte)((value & 0x7f) | 0x80)); value >>= 7; }
            body.AddRange(stack);
        }
        return Tlv(0x06, body.ToArray());
    }

    public static byte[] IntegerSmall(int value)
    {
        if (value == 0) return new byte[] { 0x02, 0x01, 0x00 };
        var bytes = new List<byte>();
        int n = value;
        while (n > 0) { bytes.Insert(0, (byte)(n & 0xff)); n >>= 8; }
        if ((bytes[0] & 0x80) != 0) bytes.Insert(0, 0);
        return Tlv(0x02, bytes.ToArray());
    }

    public static byte[] IntegerFromBytes(byte[] magnitude)
    {
        int start = 0;
        while (start < magnitude.Length - 1 && magnitude[start] == 0) start++;
        int len = magnitude.Length - start;
        bool pad = (magnitude[start] & 0x80) != 0;
        var value = new byte[(pad ? 1 : 0) + len];
        if (pad) value[0] = 0;
        Buffer.BlockCopy(magnitude, start, value, pad ? 1 : 0, len);
        return Tlv(0x02, value);
    }

    public static byte[] OctetString(byte[] value) => Tlv(0x04, value);

    public static byte[] Null() => new byte[] { 0x05, 0x00 };

    public static byte[] Boolean(bool value) => new byte[] { 0x01, 0x01, (byte)(value ? 0xff : 0x00) };

    [StructLayout(LayoutKind.Auto)]
    public readonly struct Node
    {
        public readonly byte Tag;
        public readonly int Start;
        public readonly int ContentStart;
        public readonly int ContentEnd;
        public readonly int End;
        public Node(byte tag, int start, int contentStart, int contentEnd)
        {
            Tag = tag; Start = start; ContentStart = contentStart; ContentEnd = contentEnd; End = contentEnd;
        }
    }

    public static Node Read(byte[] bytes, int offset)
    {
        byte tag = bytes[offset];
        int pos = offset + 1;
        int length = bytes[pos++];
        if ((length & 0x80) != 0)
        {
            int num = length & 0x7f;
            length = 0;
            for (int i = 0; i < num; i++) length = (length << 8) | bytes[pos++];
        }
        return new Node(tag, offset, pos, pos + length);
    }

    public static List<Node> Children(byte[] bytes, Node parent)
    {
        var list = new List<Node>();
        int pos = parent.ContentStart;
        while (pos < parent.ContentEnd)
        {
            Node node = Read(bytes, pos);
            list.Add(node);
            pos = node.End;
        }
        return list;
    }
}
