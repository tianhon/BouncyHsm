//#:sdk Cake.Sdk@6.0.0

using Build;
using NuGet.Protocol.Core.Types;
using System.IO.Compression;

string target = Argument("target", "Default");
string configuration = Argument("Configuration", "Release");

string SourceDirectory = "./src/Src/";
string ArtifactsDirectory = "./artifacts";
string ArtifactsTmpDirectory = "./artifacts/.tmp/";

string gitCommit = "----"; //TODO
string gitBranch = "--------"; //TODO

Task(BuildTarget.RebuildDocumentation)
    .Does(() =>
    {
        DotNetRun("\"src/Tools/BouncyHsm.DocGenerator/BouncyHsm.DocGenerator.csproj",
            new ProcessArgumentBuilder().Append("./Doc/SuportedAlgorithms.md"),
            new DotNetRunSettings()
            {
                Configuration = configuration,
                MSBuildSettings = new DotNetMSBuildSettings()
                {
                    Properties =
                {
                    {"GitCommit", new List<string>() { gitCommit } }
                }
                },
                WorkingDirectory = $"src/Tools/BouncyHsm.DocGenerator",
            });
    });

Task(BuildTarget.Clean)
    .Does(() =>
    {
        DeleteDirectories(GetDirectories("./src/Src/**/obj/*"), new DeleteDirectorySettings()
        {
            Recursive = true,
            Force = true
        });

        DeleteDirectories(GetDirectories("./src/Src/**/bin/*"), new DeleteDirectorySettings()
        {
            Recursive = true,
            Force = true
        });

        CleanDirectory(ArtifactsDirectory);
    });

Task(BuildTarget.BuildBouncyHsm)
    .IsDependentOn(BuildTarget.Clean)
    .Does(() =>
    {
        string projectFile = $"{SourceDirectory}BouncyHsm/BouncyHsm.csproj";
        string outputDir = $"{ArtifactsTmpDirectory}BouncyHsm";

        DotNetPublishSettings settings = new DotNetPublishSettings()
        {
            Configuration = configuration,
            OutputDirectory = outputDir,
            MSBuildSettings = new DotNetMSBuildSettings(),
        };

        settings.MSBuildSettings.Properties.Add("GitCommit", new List<string>() { gitCommit });

        DotNetPublish(projectFile, settings);
    });

Task(BuildTarget.BuildBouncyHsmCli)
    .IsDependentOn(BuildTarget.Clean)
    .Does(() =>
    {
        string projectFile = $"{SourceDirectory}BouncyHsm.Cli/BouncyHsm.Cli.csproj";
        string outputDir = $"{ArtifactsTmpDirectory}BouncyHsm.Cli";

        DotNetPublishSettings settings = new DotNetPublishSettings()
        {
            Configuration = configuration,
            OutputDirectory = outputDir,
            MSBuildSettings = new DotNetMSBuildSettings(),
        };

        settings.MSBuildSettings.Properties.Add("GitCommit", new List<string>() { gitCommit });

        DotNetPublish(projectFile, settings);
    });

void BuildBouncyHsmPkcs11Lib(PlatformTarget platform)
{
    MSBuildSettings settings = new MSBuildSettings()
    {
        Configuration = configuration,
        PlatformTarget = platform,
        Targets =
        {
            "clean",
            "build"
        }
    };

    MSBuild($"{SourceDirectory}BouncyHsm.Pkcs11Lib/BouncyHsm.Pkcs11Lib.vcxproj", settings);
}

Task(BuildTarget.BuildPkcs11LibWin32)
    .IsDependentOn(BuildTarget.Clean)
    .Does(() =>
    {
        BuildBouncyHsmPkcs11Lib(PlatformTarget.Win32);

        string nativeLib = $"{SourceDirectory}BouncyHsm.Pkcs11Lib/{configuration}/BouncyHsm.Pkcs11Lib.dll";
        string destination = $"{ArtifactsTmpDirectory}/native/Win-x86";
        CleanDirectory(destination);
        CopyFile(nativeLib, $"{destination}/BouncyHsm.Pkcs11Lib.dll");

    });

Task(BuildTarget.BuildPkcs11LibX64)
    .IsDependentOn(BuildTarget.Clean)
    .Does(() =>
    {
        BuildBouncyHsmPkcs11Lib(PlatformTarget.x64);

        string nativeLib = $"{SourceDirectory}BouncyHsm.Pkcs11Lib/x64/{configuration}/BouncyHsm.Pkcs11Lib.dll";
        string destination = $"{ArtifactsTmpDirectory}/native/Win-x64";
        CleanDirectory(destination);
        CopyFile(nativeLib, $"{destination}/BouncyHsm.Pkcs11Lib.dll");
    });

Task(BuildTarget.BuildBouncyHsmClient)
    .IsDependentOn(BuildTarget.Clean)
    .IsDependentOn(BuildTarget.BuildPkcs11LibWin32)
    .IsDependentOn(BuildTarget.BuildPkcs11LibX64)
    .Does(() =>
    {
        string projectFile = $"{SourceDirectory}BouncyHsm.Client/BouncyHsm.Client.csproj";

        //AbsolutePath linuxNativeLibx64 = RootDirectory / "build_linux" / "BouncyHsm.Pkcs11Lib-x64.so";
        //if (linuxNativeLibx64.Exists("file"))
        //{
        //    linuxNativeLibx64.Copy(ArtifactsTmpDirectory / "native" / "Linux-x64" / "BouncyHsm.Pkcs11Lib.so", ExistsPolicy.FileOverwrite);
        //}

        //AbsolutePath rhelNativeLibx64 = RootDirectory / "build_linux" / "BouncyHsm.Pkcs11Lib-x64-rhel.so";
        //if (rhelNativeLibx64.Exists("file"))
        //{
        //    rhelNativeLibx64.Copy(ArtifactsTmpDirectory / "native" / "Rhel-x64" / "BouncyHsm.Pkcs11Lib.so", ExistsPolicy.FileOverwrite);
        //}


        DotNetPackSettings settings = new DotNetPackSettings()
        {
            Configuration = configuration,
            OutputDirectory = ArtifactsDirectory,
            MSBuildSettings = new DotNetMSBuildSettings(),
        };

        settings.MSBuildSettings.Properties.Add("RepositoryCommit", new List<string>() { gitCommit });
        settings.MSBuildSettings.Properties.Add("RepositoryBranch", new List<string>() { gitBranch });
        settings.MSBuildSettings.Properties.Add("IncludeNativeLibs", new List<string>() { "True" });

        DotNetPack(projectFile, settings);
    });

Task(BuildTarget.BuildAll)
    .IsDependentOn(BuildTarget.Clean)
    .IsDependentOn(BuildTarget.BuildPkcs11LibWin32)
    .IsDependentOn(BuildTarget.BuildPkcs11LibX64)
    .IsDependentOn(BuildTarget.BuildBouncyHsm)
    .IsDependentOn(BuildTarget.BuildBouncyHsmCli)
    .IsDependentOn(BuildTarget.BuildBouncyHsmClient)
    .Does(() =>
    {
        //TODO
    });


Task("Default")
    .Does(() =>
{
    Information("Hello from Cake.Sdk!");
});

RunTarget(target);


//Target BuildAll => _ => _
//       .DependsOn(Clean)
//       .DependsOn(BuildPkcs11LibWin32)
//       .DependsOn(BuildPkcs11LibX64)
//       .DependsOn(BuildBouncyHsm)
//       .DependsOn(BuildBouncyHsmCli)
//       .DependsOn(BuildBouncyHsmClient)
//       .Produces(ArtifactsDirectory / "*.zip")
//       .Executes(() =>
//       {
//           (ArtifactsTmpDirectory / "native").Copy(ArtifactsTmpDirectory / "BouncyHsm" / "native");
//           CreateZip(ArtifactsTmpDirectory / "native" / "Win-x64" / "BouncyHsm.Pkcs11Lib.dll",
//               "Win X64",
//               ThisVersion,
//               ArtifactsTmpDirectory / "BouncyHsm" / "wwwroot" / "native" / "BouncyHsm.Pkcs11Lib-Winx64.zip");
//           CreateZip(ArtifactsTmpDirectory / "native" / "Win-x86" / "BouncyHsm.Pkcs11Lib.dll",
//               "Win X86",
//               ThisVersion,
//               ArtifactsTmpDirectory / "BouncyHsm" / "wwwroot" / "native" / "BouncyHsm.Pkcs11Lib-Winx86.zip");

//           AbsolutePath linuxNativeLibx64 = RootDirectory / "build_linux" / "BouncyHsm.Pkcs11Lib-x64.so";
//           if (linuxNativeLibx64.Exists("file"))
//           {
//               linuxNativeLibx64.Copy(ArtifactsTmpDirectory / "BouncyHsm" / "native" / "Linux-x64" / "BouncyHsm.Pkcs11Lib.so", ExistsPolicy.FileOverwrite);
//               CreateZip(linuxNativeLibx64,
//               "Linux X64",
//               ThisVersion,
//               ArtifactsTmpDirectory / "BouncyHsm" / "wwwroot" / "native" / "BouncyHsm.Pkcs11Lib-Linuxx64.zip");
//           }
//           else
//           {
//               Log.Warning("Native lib {0} not found.", linuxNativeLibx64);
//           }

//           AbsolutePath linuxNativeLibx32 = RootDirectory / "build_linux" / "BouncyHsm.Pkcs11Lib-x86.so";
//           if (linuxNativeLibx32.Exists("file"))
//           {
//               linuxNativeLibx32.Copy(ArtifactsTmpDirectory / "BouncyHsm" / "native" / "Linux-x86" / "BouncyHsm.Pkcs11Lib.so", ExistsPolicy.FileOverwrite);

//               CreateZip(linuxNativeLibx32,
//              "Linux X86",
//              ThisVersion,
//              ArtifactsTmpDirectory / "BouncyHsm" / "wwwroot" / "native" / "BouncyHsm.Pkcs11Lib-Linuxx84.zip");
//           }
//           else
//           {
//               Log.Warning("Native lib {0} not found.", linuxNativeLibx32);
//           }

//           AbsolutePath rhelNativeLibx64 = RootDirectory / "build_linux" / "BouncyHsm.Pkcs11Lib-x64-rhel.so";
//           if (rhelNativeLibx64.Exists("file"))
//           {
//               rhelNativeLibx64.Copy(ArtifactsTmpDirectory / "BouncyHsm" / "native" / "Rhel-x64" / "BouncyHsm.Pkcs11Lib.so", ExistsPolicy.FileOverwrite);
//               CreateZip(rhelNativeLibx64,
//               "RHEL X64",
//               ThisVersion,
//               ArtifactsTmpDirectory / "BouncyHsm" / "wwwroot" / "native" / "BouncyHsm.Pkcs11Lib-RHELx64.zip");
//           }
//           else
//           {
//               Log.Warning("Native lib {0} not found.", rhelNativeLibx64);
//           }

//           (ArtifactsTmpDirectory / "BouncyHsm" / "data" / "keep.txt").TouchFile();

//           (ArtifactsTmpDirectory / "BouncyHsm").ZipTo(ArtifactsDirectory / "BouncyHsm.zip",
//               t => t.Extension != ".pdb" && t.Name != "libman.json" && t.Name != ".gitkeep" && t.Name != "appsettings.Development.json");

//           (ArtifactsTmpDirectory / "BouncyHsm.Cli").ZipTo(ArtifactsDirectory / "BouncyHsm.Cli.zip",
//              t => t.Extension != ".pdb" && t.Name != ".gitkeep");
//       });

//private void CopyLicenses(AbsolutePath csprojProjectFile, AbsolutePath outFolder)
//{
//    Log.Debug("Copy license files");
//    (RootDirectory / "LICENSE").Copy(outFolder / "License.txt");

//    try
//    {
//        AbsolutePath licensesFilePath = outFolder / "LicensesThirdParty.txt";
//        DotnetProjectLicenses($"--include-transitive --input \"{csprojProjectFile}\" -o Table --file-output \"{licensesFilePath}\" -f net8.0");
//    }
//    catch (ProcessException ex) when (ex.ExitCode == 3) // Workeround
//    {
//        Log.Warning(ex, "DotnetProjectLicenses exited with code {0}", ex.ExitCode);
//    }
//}

//private void CreateZip(AbsolutePath dllFile, string platform, string version, AbsolutePath destination)
//{
//    Log.Debug("Creating ZIP file from dll {0}", dllFile);

//    using FileStream fs = new FileStream(destination, FileMode.Create);
//    using ZipArchive archive = new ZipArchive(fs, ZipArchiveMode.Create);
//    archive.CreateEntryFromFile(dllFile, dllFile.Name, CompressionLevel.Optimal);
//    ZipArchiveEntry zipArchiveEntry = archive.CreateEntry("Readme.txt");
//    using Stream readmeStream = zipArchiveEntry.Open();

//    byte[] content = Encoding.UTF8.GetBytes(@$"Bouncy Hsm PKCS11 library

//Version: {version}
//For platform: {platform}
//Git commit: {Repository.Commit}

//Project site: https://github.com/harrison314/BouncyHsm
//License: BSD 3 Clausule
//");

//    readmeStream.Write(content);
//    readmeStream.Flush();
//}