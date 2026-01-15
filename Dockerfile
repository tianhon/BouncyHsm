# Stage 1: Build Native Library (Linux x64 - glibc)
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS linux-x64-build
RUN apt-get update && apt-get install -y clang make zip && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY src/Src/BouncyHsm.Pkcs11Lib ./src/Src/BouncyHsm.Pkcs11Lib
COPY build_linux ./build_linux
WORKDIR /build/build_linux
RUN make && zip BouncyHsm.Pkcs11Lib-Linuxx64.zip BouncyHsm.Pkcs11Lib-x64.so

# Stage 2: Build Native Library (RHEL x64)
FROM almalinux:9 AS rhel-x64-build
RUN dnf -y install gcc clang make zip && dnf clean all
WORKDIR /build
COPY src/Src/BouncyHsm.Pkcs11Lib ./src/Src/BouncyHsm.Pkcs11Lib
COPY build_linux ./build_linux
WORKDIR /build/build_linux
ENV BOUNCYOSENVIROMENT=rehl_like
RUN make && \
    mv BouncyHsm.Pkcs11Lib-x64.so BouncyHsm.Pkcs11Lib-x64-rhel.so && \
    zip BouncyHsm.Pkcs11Lib-RHELx64.zip BouncyHsm.Pkcs11Lib-x64-rhel.so

# Stage 3: Build Windows Native Libraries (Cross-compile)
FROM alpine:3.20 AS windows-build
RUN apk add --no-cache mingw-w64-gcc i686-mingw-w64-gcc make zip
WORKDIR /build
COPY src/Src/BouncyHsm.Pkcs11Lib ./src/Src/BouncyHsm.Pkcs11Lib
# Build Win x64 DLL
RUN x86_64-w64-mingw32-gcc -shared -o BouncyHsm.Pkcs11Lib.dll \
    -D_WIN32 -DCRYPTOKI_EXPORTS \
    src/Src/BouncyHsm.Pkcs11Lib/*.c \
    src/Src/BouncyHsm.Pkcs11Lib/rpc/*.c \
    src/Src/BouncyHsm.Pkcs11Lib/utils/*.c \
    -Isrc/Src/BouncyHsm.Pkcs11Lib -lws2_32 && \
    zip BouncyHsm.Pkcs11Lib-Winx64.zip BouncyHsm.Pkcs11Lib.dll

# Build Win x86 DLL
RUN i686-w64-mingw32-gcc -shared -o BouncyHsm.Pkcs11Lib.dll \
    -D_WIN32 -DCRYPTOKI_EXPORTS \
    src/Src/BouncyHsm.Pkcs11Lib/*.c \
    src/Src/BouncyHsm.Pkcs11Lib/rpc/*.c \
    src/Src/BouncyHsm.Pkcs11Lib/utils/*.c \
    -Isrc/Src/BouncyHsm.Pkcs11Lib -lws2_32 && \
    zip BouncyHsm.Pkcs11Lib-Winx86.zip BouncyHsm.Pkcs11Lib.dll

# Stage 4: Build .NET Server and SPA (Blazor WASM)
FROM mcr.microsoft.com/dotnet/sdk:9.0 AS dotnet-build
WORKDIR /src
COPY . .
RUN dotnet publish src/Src/BouncyHsm/BouncyHsm.csproj -c Release -o /app/publish -p:IncludeNativeLibs=False

# Stage 5: Final Runtime Image
FROM mcr.microsoft.com/dotnet/aspnet:8.0
WORKDIR /App

# Copy published .NET app
COPY --from=dotnet-build /app/publish .

# Copy all native ZIPs for Web UI download
RUN mkdir -p wwwroot/native
COPY --from=linux-x64-build /build/build_linux/BouncyHsm.Pkcs11Lib-Linuxx64.zip ./wwwroot/native/
COPY --from=rhel-x64-build /build/build_linux/BouncyHsm.Pkcs11Lib-RHELx64.zip ./wwwroot/native/
COPY --from=windows-build /build/BouncyHsm.Pkcs11Lib-Winx64.zip ./wwwroot/native/
COPY --from=windows-build /build/BouncyHsm.Pkcs11Lib-Winx86.zip ./wwwroot/native/

# Replicate internal native folder (Must use glibc version for Debian-based dotnet image)
RUN mkdir -p native/Linux-x64
COPY --from=linux-x64-build /build/build_linux/BouncyHsm.Pkcs11Lib-x64.so ./native/Linux-x64/BouncyHsm.Pkcs11Lib.so

# Standard configuration
EXPOSE 8080
EXPOSE 8765
VOLUME /var/BouncyHsm/
ENV ASPNETCORE_ENVIRONMENT=Docker

CMD ["dotnet", "BouncyHsm.dll"]
