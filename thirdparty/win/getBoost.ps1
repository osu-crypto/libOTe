$uri = 'https://sourceforge.net/projects/boost/files/boost/1.60.0/boost_1_60_0.zip/download'

$destination = "$PWD\boost_1_60_0.zip" 


if(!(Test-Path "$PWD\boost"))
{

    
    if(!(Test-Path $destination))
    {
        Write-Host 'downloading ' $uri ' to ' $destination
        Write-Host 'It is 131.7 MB '

        try
        { 
            Invoke-WebRequest -Uri $uri -OutFile $destination -UserAgent [Microsoft.PowerShell.Commands.PSUserAgent]::internetexplorer
        }catch
        {

            return;
        }

        Write-Host 'Download Complete'
    }


    Write-Host 'Extracting boost_1_60_0.zip to ' $PWD '. This will take a bit... So be patient.'


    Add-Type -assembly “system.io.compression.filesystem”
    [io.compression.zipfile]::ExtractToDirectory($destination, $PWD)

    mv "$PWD\boost_1_60_0" "$PWD\boost"
}

cd "$PWD\boost"

if(!(Test-Path "$PWD\b2.exe"))
{
    & $PWD\bootstrap.bat
}

.\b2.exe  toolset=msvc-14.0 architecture=x86 address-model=64 --with-thread --with-filesystem --with-regex --with-date_time stage link=static variant=debug,release runtime-link=static threading=multi



cd ..

rm $destination
