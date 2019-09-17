//Compliation:
//Win7x64: C:\Windows\Microsoft.NET\Framework64\v2.0.50727\csc.exe /r:C:\Windows\assembly\GAC_MSIL\System.Management.Automation\1.0.0.0__31bf3856ad364e35\System.Management.Automation.dll /unsafe /platform:anycpu /out:C:\Users\Public\prog.exe C:\Users\Public\prog.cs
//Win10x64: C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /r:C:\Windows\assembly\GAC_MSIL\System.Management.Automation\1.0.0.0__31bf3856ad364e35\System.Management.Automation.dll /unsafe /platform:anycpu /out:C:\Users\Public\prog.exe C:\Users\Public\prog.cs
//Insert function call in end of powershell script eg. Invoke-AllChecks -Verbose | Out-File C:\Users\Public\allchecks.txt
//Usage: prog.exe "path_to_powershell_file"

using System;

using System.Configuration.Install;

using System.Runtime.InteropServices;

using System.Management.Automation.Runspaces;



public class Program

{

    public static void Main( string[] args )

    {

     Mycode.Exec( args[ 0 ] );

    }

}

public class Mycode

{

    public static void Exec(string file)

    {

     string command = System.IO.File.ReadAllText( file );

     RunspaceConfiguration rspacecfg = RunspaceConfiguration.Create();

     Runspace rspace = RunspaceFactory.CreateRunspace( rspacecfg );

     rspace.Open();

     Pipeline pipeline = rspace.CreatePipeline();

    pipeline.Commands.AddScript( command );

     pipeline.Invoke();

    }

}