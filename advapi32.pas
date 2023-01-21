unit advapi32;

{$mode delphi}

interface

//uses windows,SysUtils;

function CryptStringToBinary(pszString: PChar; cchString: dword; dwFlags: dword;
         pbBinary: pointer; pcbBinary: pdword; pdwSkip: pdword;
         pdwFlags: pdword): boolean; stdcall;external 'crypt32.dll';

function CryptBinaryToString(pbBinary: pointer; cbBinary: dword; dwFlags: dword;
         pszString: PChar; pcchString: pdword): boolean; stdcall;external 'crypt32.dll';

function CryptStringToBinaryA(pszString: PChar; cchString: dword; dwFlags: dword;
         pbBinary: pointer;  pcbBinary: pdword; pdwSkip: pdword;
         pdwFlags: pdword): boolean; stdcall;external 'crypt32.dll';

function CryptBinaryToStringA(pbBinary: pointer; cbBinary: dword; dwFlags: dword;
         pszString: PChar; pcchString: pdword): boolean; stdcall;external 'crypt32.dll';

function CryptStringToBinaryW(pszString: PWideChar; cchString: dword; dwFlags: dword;
         pbBinary: pointer; pcbBinary: pdword; pdwSkip: pdword;
         pdwFlags: pdword): boolean; stdcall;external 'crypt32.dll';

function CryptBinaryToStringW(pbBinary: pointer; cbBinary: dword; dwFlags: dword;
         pszString: PWideChar; pcchString: pdword): boolean; stdcall;external 'crypt32.dll';

implementation

end.

