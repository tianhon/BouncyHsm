using BouncyHsm.Core.Services.Contracts.P11;
using Org.BouncyCastle.Crypto;
using System;

namespace BouncyHsm.Core.Services.P11Handlers.Common;

internal class CloudHsmAesGcmBufferedCipher : IBufferedCipher
{
    private readonly IBufferedCipher inner;
    private readonly byte[] iv;
    private bool ivProcessed = false;

    public CloudHsmAesGcmBufferedCipher(IBufferedCipher inner, byte[] iv)
    {
        this.inner = inner;
        this.iv = iv;
    }

    public string AlgorithmName => this.inner.AlgorithmName;

    public void Init(bool forEncryption, ICipherParameters parameters)
    {
        this.inner.Init(forEncryption, parameters);
        this.ivProcessed = false;
    }

    public int GetUpdateOutputSize(int inputLen)
    {
        return this.inner.GetUpdateOutputSize(inputLen) + (this.ivProcessed ? 0 : this.iv.Length);
    }

    public int GetOutputSize(int inputLen)
    {
        return this.inner.GetOutputSize(inputLen) + (this.ivProcessed ? 0 : this.iv.Length);
    }

    public byte[] ProcessByte(byte input)
    {
        byte[] innerResult = this.inner.ProcessByte(input) ?? Array.Empty<byte>();
        if (!this.ivProcessed)
        {
            byte[] result = new byte[this.iv.Length + innerResult.Length];
            Array.Copy(this.iv, 0, result, 0, this.iv.Length);
            Array.Copy(innerResult, 0, result, this.iv.Length, innerResult.Length);
            this.ivProcessed = true;
            return result;
        }
        return innerResult;
    }

    public int ProcessByte(byte input, byte[] output, int outOff)
    {
        int written = 0;
        if (!this.ivProcessed)
        {
            Array.Copy(this.iv, 0, output, outOff, this.iv.Length);
            outOff += this.iv.Length;
            written += this.iv.Length;
            this.ivProcessed = true;
        }
        return written + this.inner.ProcessByte(input, output, outOff);
    }

    public int ProcessByte(byte input, Span<byte> output)
    {
        int written = 0;
        if (!this.ivProcessed)
        {
            this.iv.AsSpan().CopyTo(output);
            output = output.Slice(this.iv.Length);
            written += this.iv.Length;
            this.ivProcessed = true;
        }
        return written + this.inner.ProcessByte(input, output);
    }

    public byte[] ProcessBytes(byte[] input)
    {
        byte[] innerResult = this.inner.ProcessBytes(input) ?? Array.Empty<byte>();
        if (!this.ivProcessed && input.Length > 0)
        {
            byte[] result = new byte[this.iv.Length + innerResult.Length];
            Array.Copy(this.iv, 0, result, 0, this.iv.Length);
            Array.Copy(innerResult, 0, result, this.iv.Length, innerResult.Length);
            this.ivProcessed = true;
            return result;
        }
        return innerResult;
    }

    public byte[] ProcessBytes(byte[] input, int inOff, int length)
    {
        byte[] innerResult = this.inner.ProcessBytes(input, inOff, length) ?? Array.Empty<byte>();
        if (!this.ivProcessed && length > 0)
        {
            byte[] result = new byte[this.iv.Length + innerResult.Length];
            Array.Copy(this.iv, 0, result, 0, this.iv.Length);
            Array.Copy(innerResult, 0, result, this.iv.Length, innerResult.Length);
            this.ivProcessed = true;
            return result;
        }
        return innerResult;
    }

    public int ProcessBytes(byte[] input, byte[] output, int outOff)
    {
        return this.ProcessBytes(input, 0, input.Length, output, outOff);
    }

    public int ProcessBytes(byte[] input, int inOff, int length, byte[] output, int outOff)
    {
        int written = 0;
        if (!this.ivProcessed && length > 0)
        {
            Array.Copy(this.iv, 0, output, outOff, this.iv.Length);
            outOff += this.iv.Length;
            written += this.iv.Length;
            this.ivProcessed = true;
        }
        return written + this.inner.ProcessBytes(input, inOff, length, output, outOff);
    }

    public int ProcessBytes(ReadOnlySpan<byte> input, Span<byte> output)
    {
        int written = 0;
        if (!this.ivProcessed && !input.IsEmpty)
        {
            this.iv.AsSpan().CopyTo(output);
            output = output.Slice(this.iv.Length);
            written += this.iv.Length;
            this.ivProcessed = true;
        }
        return written + this.inner.ProcessBytes(input, output);
    }

    public byte[] DoFinal()
    {
        byte[] innerResult = this.inner.DoFinal() ?? Array.Empty<byte>();
        if (!this.ivProcessed)
        {
            byte[] result = new byte[this.iv.Length + innerResult.Length];
            Array.Copy(this.iv, 0, result, 0, this.iv.Length);
            Array.Copy(innerResult, 0, result, this.iv.Length, innerResult.Length);
            this.ivProcessed = true;
            return result;
        }
        return innerResult;
    }

    public byte[] DoFinal(byte[] input)
    {
        byte[] innerResult = this.inner.DoFinal(input) ?? Array.Empty<byte>();
        if (!this.ivProcessed)
        {
            byte[] result = new byte[this.iv.Length + innerResult.Length];
            Array.Copy(this.iv, 0, result, 0, this.iv.Length);
            Array.Copy(innerResult, 0, result, this.iv.Length, innerResult.Length);
            this.ivProcessed = true;
            return result;
        }
        return innerResult;
    }

    public byte[] DoFinal(byte[] input, int inOff, int length)
    {
        byte[] innerResult = this.inner.DoFinal(input, inOff, length) ?? Array.Empty<byte>();
        if (!this.ivProcessed)
        {
            byte[] result = new byte[this.iv.Length + innerResult.Length];
            Array.Copy(this.iv, 0, result, 0, this.iv.Length);
            Array.Copy(innerResult, 0, result, this.iv.Length, innerResult.Length);
            this.ivProcessed = true;
            return result;
        }
        return innerResult;
    }

    public int DoFinal(byte[] output, int outOff)
    {
        int written = 0;
        if (!this.ivProcessed)
        {
            Array.Copy(this.iv, 0, output, outOff, this.iv.Length);
            outOff += this.iv.Length;
            written += this.iv.Length;
            this.ivProcessed = true;
        }
        return written + this.inner.DoFinal(output, outOff);
    }

    public int DoFinal(byte[] input, byte[] output, int outOff)
    {
        return this.DoFinal(input, 0, input.Length, output, outOff);
    }

    public int DoFinal(byte[] input, int inOff, int length, byte[] output, int outOff)
    {
        int written = 0;
        if (!this.ivProcessed)
        {
            Array.Copy(this.iv, 0, output, outOff, this.iv.Length);
            outOff += this.iv.Length;
            written += this.iv.Length;
            this.ivProcessed = true;
        }
        return written + this.inner.DoFinal(input, inOff, length, output, outOff);
    }

    public int DoFinal(ReadOnlySpan<byte> input, Span<byte> output)
    {
        int written = 0;
        if (!this.ivProcessed)
        {
            this.iv.AsSpan().CopyTo(output);
            output = output.Slice(this.iv.Length);
            written += this.iv.Length;
            this.ivProcessed = true;
        }
        return written + this.inner.DoFinal(input, output);
    }

    public int DoFinal(Span<byte> output)
    {
        int written = 0;
        if (!this.ivProcessed)
        {
            this.iv.AsSpan().CopyTo(output);
            output = output.Slice(this.iv.Length);
            written += this.iv.Length;
            this.ivProcessed = true;
        }
        return written + this.inner.DoFinal(output);
    }

    public void Reset()
    {
        this.inner.Reset();
        this.ivProcessed = false;
    }

    public int GetBlockSize()
    {
        return this.inner.GetBlockSize();
    }
}
