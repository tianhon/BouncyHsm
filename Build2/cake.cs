#:sdk Cake.Sdk

var target = Argument("target", "Default");

Task("Default")
    .Does(() =>
{
    Information("Hello from Cake.Sdk!");
});

RunTarget(target);
