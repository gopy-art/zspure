@echo off
echo Hello Windows Users
echo The integration-test will start under 5 seconds ...
echo Build the tool ...
go build
timeout 5
for %%f in (.\templates\*.html) do (
    echo [INPUT] file = %%f
    zspure.exe file --file %%f --json
    echo.
)
for %%f in (.\templates\zgrab2\*.json) do (
    echo [INPUT] file = %%f
    zspure.exe file --file %%f --zgrab-input --json
    echo.
)
echo Done