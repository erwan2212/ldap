  {      LDAPAdmin - Constant.pas
  *      Copyright (C) 2003-2016 Tihomir Karlovic
  *
  *      Author: Tihomir Karlovic
  *
  *
  * This file is free software; you can redistribute it and/or modify
  * it under the terms of the GNU General Public License as published by
  * the Free Software Foundation; either version 2 of the License, or
  * (at your option) any later version.
  *
  * This file is distributed in the hope that it will be useful,
  * but WITHOUT ANY WARRANTY; without even the implied warranty of
  * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  * GNU General Public License for more details.
  *
  * You should have received a copy of the GNU General Public License
  * along with this program; if not, write to the Free Software
  * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
  }

unit Constant;

interface

const
  bmRoot               =  0;
  bmRootSel            =  1;
  bmEntry              =  2;
  bmEntrySel           =  3;
  bmPosixUser          =  4;
  bmPosixUserSel       =  4;
  bmSamba3User         =  5;
  bmSamba3UserSel      =  5;
  bmADUser             =  5;
  bmADUserSel          =  5;
  bmGroup              =  6;
  bmGroupSel           =  6;
  bmComputer           =  7;
  bmComputerSel        =  7;
  bmAdComputer         =  7;
  bmAdComputerSel      =  7;
  bmMailGroup          =  9;
  bmMailGroupSel       =  9;
  bmDelete             = 12;
  bmOu                 = 13;
  bmOuSel              = 13;
  bmTransport          = 15;
  bmTransportSel       = 15;
  bmSamba2User         = 19;
  bmSamba2UserSel      = 19;
  bmSudoer             = 21;
  bmSudoerSel          = 21;
  bmHost               = 22;
  bmHostSel            = 22;
  bmNetwork            = 23;
  bmNetworkSel         = 23;
  bmLocality           = 24;
  bmLocalitySel        = 24;
  bmSambaDomain        = 25;
  bmSambaDomainSel     = 25;
  bmIdPool             = 26;
  bmIdPoolSel          = 26;
  bmSchema             = 27;
  bmSchemaSel          = 27;
  bmLocked             = 28;
  bmLockedSel          = 28;
  bmUnlocked           = 29;
  bmUnlockedSel        = 29;
  bmRegistry           = 32;
  bmFileStorage        = 33;
  bmGrOfUnqNames       = 35;
  bmGrOfUnqNamesSel    = 35;
  bmSambaGroup         = 39;
  bmSambaGroupSel      = 39;
  bmADGroup            = 39;
  bmADGroupSel         = 39;
  bmClassSchema        = 40;
  bmClassSchemaSel     = 40;
  bmAttributeSchema    = 41;
  bmAttributeSchemaSel = 41;
  bmConfiguration      = 42;
  bmConfigurationSel   = 42;
  bmAdContainer        = 43;
  bmAdContainerSel     = 43;
  bmAlias              = 44;
  bmAliasSel           = 44;
  bmTemplateEntry      = 45;
  bmTemplateEntrySel   = 45;
  bmOverlayTemplate    = 46;
  bmOverlayDisabled    = 47;

  ncDummyNode          = -1;

// Registry strings

  REG_KEY              = 'Software\LdapAdmin\';
  REG_ACCOUNT          = 'Accounts';
  REG_CONFIG           = 'Config';

// System

  SAMBA_VERSION2       = 2;
  SAMBA_VERSION3       = 3;

  POSIX_ID_NONE        = 0;
  POSIX_ID_RANDOM      = 1;
  POSIX_ID_SEQUENTIAL  = 2;
  FIRST_UID            = 1000;
  LAST_UID             = 65534;
  FIRST_GID            = 1000;
  LAST_GID             = 65534;

  NO_GROUP             = 65534;
  COMPUTER_GROUP       = NO_GROUP;

  COMBO_HISTORY        = 10;

  ScrollAccMargin  = 40;

type
  TEditMode            = (EM_ADD, EM_MODIFY);

const

// Registry names

  rAccountFiles       = 'ConfigFiles';
  rBookmarks          = 'Bookmarks\Bookmarks';
  rBookmarksMenuShow  = 'Bookmarks\ShowBookmarksInMenu';
  rBookmarksTreeShow  = 'Bookmarks\ShowBookmarksInTree';
  rDirectoryType      = 'Connection\DirectoryType';
  rDontCheckProto     = 'DontCheckProto';
  rEditorSchemaHelp   = 'General\EdSchemaHelp';
  rEncodedLdapStrings = 'EncodedStrings';
  rEvViewStyle        = 'EvViewStyle';
  rInetDisplayName    = 'Inet\DisplayName';
  rLanguage           = 'Language';
  rLanguageDir        = 'LanguageDir';
  rLastMemberOf       = 'General\LastMemberOf';
  rLocalTransTable    = 'TranscodeTable';
  rMwLTEnfContainer   = 'MwLTEnfContainer';
  rMwLTIdentObject    = 'MwLTIdObject';
  rMwLTWidth          = 'MwLTWidth';
  rMwShowEntries      = 'MwShowEntries';
  rMwShowValues       = 'MwShowValues';
  rMwTreeSplit        = 'MwHSplit';
  rMwViewSplit        = 'MwVSplit';
  rPosixFirstGID      = 'Posix\FirstGID';
  rPosixFirstUID      = 'Posix\FirstUID';
  rPosixGroup         = 'Posix\Group';
  rPosixGroupOfUnames = 'Posix\PosixGroupOfUniqueNames';
  rPosixHomeDir       = 'Posix\HomeDir';
  rPosixIDType        = 'Posix\IdType';
  rPosixLastGID       = 'Posix\LastGID';
  rPosixLastUID       = 'Posix\LastUID';
  rPosixLoginShell    = 'Posix\LoginShell';
  rPosixPwdHashType   = 'Posix\PwdHashType';
  rPosixUserName      = 'Posix\UserName';
  rPostfixMailAddress = 'Postfix\MailAddress';
  rPostfixMaildrop    = 'Postfix\Maildrop';
  rQuickSearchFilter  = 'QuickSearchFilter';
  rRenamePrompt       = 'RenamePrompt';
  rAdDisplayName      = 'Ad\DisplayName';
  rAdCommonName       = 'Ad\CommonName';
  rAdHomeDrive        = 'Ad\HomeDrive';
  rAdHomeDirectory    = 'Ad\HomeDir';
  rAdNTDomain         = 'Ad\NTDomain';
  rAdNTLoginName      = 'Ad\NTLogonName';
  rAdProfilePath      = 'Ad\ProfilePath';
  rAdLoginScript      = 'Ad\Script';
  rAdUPNDomain        = 'Ad\UPNDomain';
  rAdUserPrincipalName= 'Ad\UserPrincipalName';
  rSambaDomainName    = 'Samba\DomainName';
  rSambaHomeDrive     = 'Samba\HomeDrive';
  rSambaHomeShare     = 'Samba\HomeShare';
  rSambaLMPasswords   = 'Samba\LMPasswords';
  rSambaNetbiosName   = 'Samba\NetbiosName';
  rSambaProfilePath   = 'Samba\ProfilePath';
  rSambaScript        = 'Samba\Script';
  rSambaRidMethod     = 'Samba\RidMethod';
  rSearchHeight       = 'Search\Height';
  rSearchWidth        = 'Search\Width';
  rSearchAttributes   = 'Search\Attributes';
  rSearchBase         = 'Search\Base';
  rSearchCustFilters  = 'Search\Filters\';
  rSearchRegEx        = 'Search\RegEx\';
  rSearchDerefAliases = 'Search\DereferenceAliases';
  rSearchFilter       = 'SearchFilter';
  rSearchScope        = 'Search\Scope';
  rSearchRegExGreedy  = 'Search\RegExGreedy';
  rSearchRegExMulti   = 'Search\RegExMultiline';
  rSearchRegExCase    = 'Search\RegExCase';
  rSmartDelete        = 'SmartDelete';
  rStartupSession     = 'StartupSession';
  rTabCache           = 'TabCache';
  rTemplateAutoload   = 'TemplateAutoload';
  rTemplateDir        = 'TemplateDir';
  rTemplateExtensions = 'TemplateExtensions';
  rTemplateFormHeight = 'TemplateForm\Height';
  rTemplateFormWidth  = 'TemplateForm\Width';
  rTemplateProperties = 'TemplateProperites';
  rUseTemplateImages  = 'UseTemplateImages';
  rWarnDTAutodetect   = 'WarnDTAuto';

// Search filters

  sADCOMPUTERS      = '(objectclass=computer)';
  sANYCLASS         = '(objectclass=*)';
  sSAMBAACCNT       = '(objectclass=sambaAccount)';
  sPOSIXACCNT       = '(objectclass=posixAccount)';
  sMAILACCNT        = '(objectclass=mailUser)';
  sPOSIXGROUPS      = '(objectclass=posixGroup)';
  sCOMPUTERS        = '(&'+sPOSIXACCNT+'(uid=*$))';
  sUSERS            = '(&'+sPOSIXACCNT+'(!(uid=*$)))';
  sMAILGROUPS       = '(objectclass=mailGroup)';
  {sMY_GROUP         = '(|(&(objectclass=posixGroup)(memberUid=%s))'  +
                        '(&(objectclass=groupOfNames)(member=%1:s))' +
                        '(&(objectclass=groupOfUniqueNames)(uniqueMember=%1:s)))';}
  sMY_AUTHGROUPS    = '(&(objectclass=posixGroup)(|(memberUid=%s)(member=%1:s)(uniqueMember=%1:s)))';
  sMY_POSIX_GROUPS  = '(&(objectclass=posixGroup)(memberUid=%s))';
  sMY_SAMBAGROUPS   = '(&(objectclass=sambaGroupMapping)(|(memberUid=%s)(member=%1:s)(uniqueMember=%1:s)))';
  sMY_MAILGROUPS    = '(&(objectclass=mailGroup)(member=%s))';
  sMY_GROUPS        = '(|(&(objectclass=posixGroup)(memberUid=%s))'  +
                      '(&(|(objectclass=groupOfNames)(objectclass=mailGroup))(member=%1:s))' +
                      '(&(objectclass=groupOfUniqueNames)(uniqueMember=%1:s)))';
  sMY_DN_GROUPS     = '(|(&(|(objectclass=groupOfNames)(objectclass=mailGroup))(member=%0:s))' +
                      '(&(objectclass=groupOfUniqueNames)(uniqueMember=%0:s)))';
  sNMY_AUTHGROUPS   = '(&(objectclass=posixGroup)(!(|(memberUid=%s)(member=%1:s)(uniqueMember=%1:s))))';
  sNMY_POSIX_GROUPS = '(&(objectclass=posixGroup)(!(memberUid=%s)))';
  sNMY_SAMBAGROUPS  = '(&(objectclass=sambaGroupMapping)(!(|(memberUid=%s)(member=%1:s)(uniqueMember=%1:s))))';
  sNMY_MAILGROUPS   = '(&(objectclass=mailGroup)(!(member=%s)))';
  sNMY_GROUPS       = '(|(&(objectclass=posixGroup)(!(memberUid=%s)))'  +
                      '(&(|(objectclass=groupOfNames)(objectclass=mailGroup))(!(member=%1:s)))' +
                      '(&(objectclass=groupOfUniqueNames)(!(uniqueMember=%1:s))))';
  sGROUPBYGID       = '(&(objectclass=posixGroup)(gidNumber=%d))';
  sACCNTBYUID       = '(&(objectclass=posixAccount)(uid=%s))';
  sDEFQUICKSRCH     = '(|(cn=*%s*)(uid=*%s*)(displayName=*%s*))';
  sDEFSRCH          = '(|(uid=*%s*)(displayName=*%s*)(cn=*%s*)(sn=*%s*))';

resourcestring

  LAC_NOTLAC               = 'The file "%s" is not an Ldap Admin accounts file';
  BAD_XML_DOCUMENT         = 'Not a well formed XML file.';
  XML_BAD_CLOSE_TAG        = 'The "%s" is expected, but the "%s" is received';
  XML_UNEXPECTED_CLOSE_TAG = 'Unexpected closing tag "%s"';
  XML_NO_OPENING_TAG       = 'No opening tag!';

  SAVE_SEARCH_FILTER       = 'Ldif file, Windows format (CR/LF) (*.ldif)|*.ldif|Ldif file, Unix format (LF only) (*.ldif)|*.ldif|CSV (Comma-separated) (*.csv)|*.csv|XML (*.xml)|*.xml';
  SAVE_MODIFY_FILTER       = 'LDAP Admin batch file (*.lbf)|*.lbf';
  SAVE_MODIFY_LOG_FILTER   = 'Text file (*.txt)|*.txt';

  CONNLIST_SAVE_FILTER     = 'Account Files (*.lcf)|*.lcf|All Files (*.*)|*.*';


// Captions

  cAdd              = '&Add';
  cAddAddress       = 'Add Address';
  cAddAttribute     = 'Add attribute...';
  cAddConn          = 'New connection';
  cAddDelReplace    = 'Add,Delete,Replace';
  cAddHost          = 'Add Host';
  cAddValue         = 'Add value';
  cAnonymousConn    = 'Anonymous connection';
  cAppName          = 'LDAP Admin';
  cAttribute        = 'Attribute';
  cAttributeName    = 'Attribute name:';
  cBinary           = 'Binary';
  cBrowse           = '&Browse...';
  cCancel           = '&Cancel';
  cCert             = 'Certificate';
  cClose            = '&Close';
  cColumnNames      = 'Name,DN';
  cConfirm          = 'Confirmation';
  cCopying          = 'Copying...';
  cCopySelection    = 'Copy selection to...';
  cCopyTo           = 'Copy %s to...';
  //cCommonName       = 'Common name';
  cCreateFolder     = 'Create folder';
  cCurrentConn      = 'Current connection';
  cDecimal          = 'Decimal:';
  cDelete           = '&Delete';
  cDeleting         = 'Deleting:';
  cDescription      = 'Description';
  cDetails          = '&Details';
  cEdit             = '&Edit';
  cEditAddress      = 'Edit Address';
  cEditEntry        = 'Edit entry';
  cEditHost         = 'Edit Host';
  cEditResource     = 'Edit Resource';
  cEditValue        = 'Edit value';
  cEMail            = '&E-Mail';
  cEnglish          = 'English';
  cEnterNewValue    = 'Enter new value:';
  cEnterPasswd      = 'Enter password';
  cEnterRDN         = 'Enter rdn:';
  cError            = 'Error';
  cFinish           = '&Finish';
  cFolderName       = 'Folder name:';
  cHex              = 'Hex:';
  cHomeDir          = 'Home Directory';
  cHostName         = 'Host Name:';
  cImage            = 'Image';
  cInformation      = 'Information';
  cIpAddress        = 'IP Address';
  cLoadBatchFromFile= 'Load batch from file';
  cMaildrop         = 'Maildrop';
  cMerge            = 'Merge';
  cMidnight         = 'Midnight';
  cModifyOk         = 'Ok.';
  cModifySkipped    = 'Skipped.';
  cMore             = 'More...';
  cMoveTo           = 'Move %s to...';
  cMoving           = 'Moving...';
  cName             = 'Name';
  cNew              = '<<new>>';
  cNewEntry         = 'New entry';
  cNewItem          = 'New item';
  cNewName          = 'New name:';
  cNewResource      = 'New Resource';
  cNewSubmenu       = 'New submenu';
  cNewValue         = 'New value';
  cNext             = '&Next';
  cObjectclass      = 'Objectclass';
  cOk               = '&OK';
  cOldValue         = 'Old value';
  cOperation        = 'Operation:';
  cOverwrite        = 'Overwrite';
  cParentDir        = 'Parent directory:';
  cPassword         = 'Password:';
  cPath             = 'Path: %s';
  cPickAccounts     = 'Choose Accounts';
  cPickGroups       = 'Choose Groups';
  cPickMembers      = 'Choose members';
  cPickQuery        = 'Choose query';
  cPreparing        = 'Preparing...';
  cProgress         = 'Progress:';
  cPropertiesOf     = 'Properties of %s';
  cRegistryCfgName  = 'Private';
  cRename           = 'Rename';
  cResource         = 'Resource:';
  cRetry            = '&Retry';
  cSambaDomain      = 'Samba Domain';
  cSASLCurrUSer     = 'Use current user credentials';
  cSaveBatchProtocol= 'Save protocol';
  cSaveBatchToFile  = 'Save batch to file';
  cSaveToLdap       = 'Save to LDAP';
  cSearchBase       = 'Search base';
  cSearchResults    = 'Search results:';
  cSelectAliasDir   = 'Select alias directory';
  cSelectEntry      = 'Select entry';
  cServer           = 'Server: %s';
  cSetPassword      = 'Set password...';
  cSkip             = '&Skip';
  cSkipAll          = 'Skip &all';
  cSmartDelete      = '&Smart delete';
  cSmtpAddress      = 'SMTP Address:';
  cSaveSrchResults  = 'Save search results';
  cSurname          = 'Second name';
  cText             = 'Text';
  cUnknown          = 'Unknown';
  {cUpnPrefix        = 'UPN-Prefix';
  cUpnSuffix        = 'UPN-Suffix';}
  cUser             = 'User: %s';
  cUsername         = 'Username';
  cUserPrompt       = 'User Prompt';
  cValue            = 'Value';
  cView             = '&View';
  cViewPic          = 'View picture: ';
  cWarning          = 'Warning';

// Menu captions

  mcNew               = '&New...';
  mcEntry             = '&Entry...';
  mcUser              = '&User...';
  mcComputer          = '&Computer...';
  mcGroup             = '&Group...';
  mcMailingList       = '&Mailing list...';
  mcTransportTable    = '&Transport table...';
  mcOu                = '&Organizational unit...';
  mcHost              = '&Host...';
  mcLocality          = '&Locality...';
  mcGroupOfUN         = 'Grou&p of unique names...';
  mcAlias             = 'Alias...';
  mcAdContainer       = 'Container...';

// Messages

  stConnectSuccess  = 'Connection is successful.';
  stAbortScript     = 'Do you want to abort the script?';
  stAccntExist      = 'Account with name "%s" already exists!';
  stAccntNameReq    = 'You have to enter a name for this connection!';
  stAllFilesFilter  = 'All files (*.*)|*.*';
  stArgDecNum       = 'Argument must be a decimal number: %s!';
  stAssertDecNum    = 'Assertion value %s must be decimal number!';
  stAskTreeCopy     = 'Copy %s to %s?';
  stAskTreeMove     = 'Move %s to %s?';
  stAutodetectDT    = 'Manually setting of this option is not recommended! Unless you are certain that there is a problem with autodetection it is recommended to let LdapAdmin detect the directory type.';
  stBinaryMatchDn   = 'Binary match on dn is not allowed!';
  stCantStorPass    = 'This storage can not store passwords';
  stCertConfirmConn = 'The server you are trying to connect to is using a certificate which could not be verified!'#10#13#10#13'%s'#10#13'Do you want to proceed?';
  stCertInvalidName = 'The name of the security certificate is invalid or does not match the server name!';
  stCertInvalidSig  = 'Signature check failed!';
  stCertInvalidTime = 'The security certificate has expired or is not yet valid!';
  stCertNotFound    = 'Issuer certificate not found';
  stCertOpenStoreErr= 'Error opening certificate system store %s: %s!';
  stCertSelfSigned  = 'The certificate is self-signed root certificate';
  stClassNotFound   = 'Class %s not found!';
  stChangePwdSetErr = 'An attempt to set user change password priviledge failed: ';
  stChangePwdGetErr = 'An attempt to retrieve user change password priviledge failed: ';
  stCntObjects      = '%d object(s) retrieved.';
  stCntSubentries   = '%d subentries';
  stConfirmDel      = 'Delete entry "%s"?';
  stConfirmDelAccnt = 'Delete account "%s"?';
  stConfirmMultiDel = 'Delete %d entries?';
  stConvErrSambaRid = 'Error converting sambaNextRid:';
  stDateFormat      = 'date format';
  stDeleteAll       = '"%s"'#10#13'This directory entry is not empty (it contains further leaves). Delete all recursively?';
  stDeleteFolder    = 'Delete folder "%s"?';
  stDeleteMenuItem  = 'Delete this menu item?';
  stDeleteSelected  = 'Delete selected?';
  stDeleteSubmenu   = 'Delete this submenu?';
  stDelNamingAttr   = 'Attribute %s is the naming value of this entry! Do you want to delete it?';
  stDirNotExists    = 'Directory does not exist: %s!';
  stDisplaying      = 'Displaying first %d results.';
  stDoNotCheckAgain = 'Do not perform this check in the future.';
  stDoNotShowAgain  = 'Do not show this message in the future.';
  stDuplicateEntry  = 'EntryList does not allow duplicates';
  stDuplicateSC     = 'Shortcut ''%s'' is already assigned to ''%s'' menu item!';
  stEmptyArg        = 'Empty argument!';
  stEmptyFile       = 'File %s is empty!';
  stErrExtMethName  = 'Error extracting method name!';
  stErrUnaryOp      = 'Unary operator "%s" can not be applied to multiple operands: %s!';
  stEvTypeEvTypeErr = 'Error setting %s event: %s event type is not supported!';
  stExtConfirmAssoc = 'LDAPAdmin is currently not your default LDAP browser.'+#10+'Would you like to make it your default LDAP browser?';
  stExpectedAt      = 'Expected %s at %s!';
  stExpectedEndOfStr= 'Expected end of string but found "%s" at %s!';
  stExpectedButReceived = 'Expected "=" but recieved "';
  stExportAccounts  = 'Export accounts';
  stExportSelect    = 'Select items to export:';
  stExportSuccess   = 'Success: %d Object(s) succesfully exported!';
  stFileModified    = 'File %s was modifed. Save changes?';
  stFileOverwrite   = 'File ''%s'' exists, overwrite?';
  stFileReadOnly    = 'File opened in read only mode!';
  stFolderExists    = 'Folder with name "%s" already exists.';
  stFolderMerge     = 'Folder with name "%s" already exists. Merge or save with different name?';
  stFolderNameReq   = 'You have to enter a name for this folder!';
  stFolderNotEmpty  = 'The folder "%s" is not empty. Delete anyway?';
  stGetProcAddrErr  = 'Cannot GetProcAddress of %s.';
  stGidNotSamba     = 'Selected primary group is not a Samba group or it does not map to user domain. Do you still want to continue?';
  stGroupMailReq    = 'You have to enter at least one mail address for this group!';
  stGroupNameReq    = 'You have to enter a name for this group!';
  stIdentIsnotValid = '"%s" is not a valid %s!';
  stImgInvalidForm  = 'Image format not supported!';
  stImportAccounts  = 'Import accounts';
  stImportSelect    = 'Select items to import:';
  stImportTo        = 'Import to:';
  stInserting       = 'Inserting, %d of %d. Press ESC to abort...';
  stInteger         = 'integer number';
  stInvalidArgIndex = 'Invalid Argument Index: %d';
  stInvalidChr      = 'Invalid character: "%s" in "%s"!';
  stInvalidChar     = '%s may not contain the character "%s"';
  stInvalidChars    = '%s may not contain any of the following characters:'#10'%s';
  stInvalidCmdVer   = 'Invalid LDAP version in command line: %s';
  stInvalidFilter   = 'Invalid or unsupported filter type: %s!';
  stInvalidLdapOp   = 'Invalid Ldap operation!';
  stInvalidOperator = 'Invalid operator "%s"!';
  stInvalidSid      = 'Could not set "User cannot change password" flag.'#10#10'Error message: %s'#10#10'Probable reason: the computer %s is not a member of the domain %s or a trusted domain.';
  stInvalidTagValue = 'Invalid value %s for <%s>!';
  stInvalidTimeFmt  = 'Invalid time format: %s!';
  stInvalidURL      = 'Invalid URL format!';
  stLdapError       = 'LDAP error: %s!';
  stLdapErrorEx     = 'LDAP error! %s: %s.';
  stLdifEFold       = 'Line %d: Empty line may not be folded!';
  stLdifEInvMode    = 'Internal error: Invalid LDIF mode!';
  stLdifENoCol      = 'Line %d: Missing ":".';
  stLdifENoDn       = 'Line %d: dn expected but %s found!';
  stLdifEof         = 'End of file reached!';
  stLdifEVer        = 'Invalid version value: %s!';
  stLdifFailure     = '%d Object(s) could not be imported!';
  stLdifInvalidUrl  = 'Invalid URL!';
  stLdifInvAttrName = 'Line %d: Invalid attribute name, expected "%s" but found "%s"!';
  stLdifInvChType   = 'Line %d: Invalid changetype "%s"!';
  stLdifInvOp       = 'Line %d: Invalid operation "%s"!';
  stLdifNotExpected = 'Line %d: Expected "%s" but found "%s"!';
  stLdifSuccess     = '%d Object(s) succesfully imported!';
  stLdifUrlNotSupp  = 'URL method not supported!';
  stMenuAssignTempl = 'A template name must not be empty!';
  stMenuLocateTempl = 'The template "%s" which is assigned to this action could not be located!';
  stMissingIn       = 'Missing %s in %s!';
  stMissingOperator = 'Missing operator!';
  stMoveOverlap     = 'Source and destination paths overlap!';
  stNeedElevated    = 'On Vista or higher, LDAPAdmin must be executed with elevated privileges for this operation to succesfully complete!';
  stNoActiveConn    = 'Connection error: could not locate active connection!';
  stNoClosingParenthesis = 'Missing closing parenthesis!';
  stNodeHasChildren = 'Node has children!';
  stNoOpeningParenthesis = 'Missing opening parenthesis!';
  stNoMoreChecks    = 'Do not perform this check in the future.';
  stNoMoreNums      = 'Pool depleted! No more available free id''s for %s!';
  stNoPosixID       = 'You should disable id creation only if you use a server side id assignment! Otherwise, you will not be able to create any users or groups.';
  stNoRdn           = 'You have to enter the unique name (rdn) for this entry!';
  stNoSchema        = 'Can''t load LDAP schema';
  stNotEnoughArgs   = 'Not enough arguments!';
  stNotLABatchFile  = '%s is not LDAPAdmin batch file!';
  stNumber          = 'number';
  stNumObjects      = '%d objects';
  stObjectNotFound  = 'Object not found: %s!';
  stObjnRetrvd      = 'Object not yet retrieved!';
  stOverwrite       = 'Do you want to overwrite?';
  stOverwriteOrRename = 'Overwrite or save under a different name?';
  stPathNotFound    = 'Path not found:%s!';
  stPassDiff        = 'Passwords do not match!';
  stPassFor         = 'Password for : %s';
  stRepeatCopyAction= 'Repeat for all';
  stRenameEntry     = 'Rename entry to %s?';
  stMutuallyExclusive = 'The options "%s" and "%s" can not be selected simultaneously!';
  stPwdInclude      = 'Include passwords';
  stPwdNotEncrypted = 'Warning: exported passwords will not be encrypted!';
  stPropReadOnly    = 'Property is read only!';
  stPwdNoEncryption = 'You are trying to change a password over a connection that is neither SSL/TLS-encrypted nor SASL-encrypted!';
  stRefUpdateError  = 'An error is occured while updating references:'#10#13'%s'#10#13'Not all references could be updated.';
  stRegAccntErr     = 'Could not read account data!';
  stRegApplying     = 'Applying regular expression...';
  stRegCntMatching  = '%s %d object(s) match regular expression.';
  stRegexError      = 'Error in regex filter: %s'#13'%s';
  stRegexFailed     = 'Regexp validation failed!';
  stReqAttr         = 'Attribute %s may not be empty!';
  stReqMail         = 'At least one E-Mail address must be defined!';
  stReqNoEmpty      = '%s must have a value!';
  stRequired        = '%s is required!';
  stResetAutolock   = 'This account has been locked down by SAMBA server! Do you want to reset the autolock flag and enable it now?';
  stResetToDefault  = 'Reset to default settings?';
  stRetryWithTrust  = 'To continue, LdapAdmin can try to create a temporary trust connection to %s by creating a \\%0:s\IPC$ share connection.'#10#10'Would you like to create a temporary trust connection to %0:s and retry the operation?';
  stRetrieving      = 'Reading: %d objects retrieved. Press ESC to abort...';
  stSaslSSL         = 'SASL encryption can not be used over an SSL connection!';
  stSchemaNoSubentry= 'Can''t find SubschemaSubentry';
  stScriptNoProc    = 'Procedure "%s" could not be located.';
  stScriptNotEvent  = 'Property ''%s'' is not an event!';
  stScriptNotSupp   = '''%s'' does not support ''%s'' event!';
  stScriptParamType = 'Unsupported parameter type!';
  stScriptSetErr    = 'Could not convert set to integer!';
  stSequentialID    = 'Activating this option could cause a significant network traffic with large user databases. Unless you REALLY need sequential id''s, leave the default option (random) on!';
  stSkipRecord      = '%s'#10#13'Skip this record?';
  stSmbDomainReq    = 'You have to select samba domain to which this group should be mapped!';
  stSorting         = 'Sorting...';
  stStopTLSError    = 'Stop TLS Failed! The connection will be closed due to unrecoverable error.';
  stTimeFormat      = 'time format';
  stTrustConnFailed = 'Could not establish trust connection to %s.'#10#10'%s';
  stTrustConnManual = 'Please create a manual connection to \\%s\IPC$ and retry the operation.';
  stTooManyArgs     = 'Too many arguments!';
  stUnclosedParam   = 'Invalid (Unclosed) parameter!';
  stUnclosedStr     = 'Unclosed string!';
  stUnclosedReference = 'Invalid (unclosed) reference: %s';
  stUnexpectedEofStr= 'Unexpected end of string: %s!';
  stUnknownValueType= 'Unknown value type.'#10'key:%s'#10'value:%s"';
  stUnsupportedAuth = 'Unsupported authentication method: %s!';
  stUnsupportedRule = 'Unsupported matching rule %s!';
  stUnsuppOperation = 'Unsupported operation: %s!';
  stUnsuppScript    = 'Unsupported script type: ';
  stUpnIncomplete   = 'User logon name is incomplete!';
  stUserBreak       = 'User break!';
  stWritePropRO     = 'Can not write to read only property!';

implementation

end.
