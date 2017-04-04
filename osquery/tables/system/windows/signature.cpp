

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <Softpub.h>

#include <string>


#include <osquery/core.h>
#include <osquery/tables.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/sql.h>

#include "osquery/core/windows/wmi.h"


namespace osquery {
namespace tables {


void genSignatureForFile(const std::string& path, QueryData& results){

  VLOG(1) << "[+] Computing sig for " << path;

  // Initialize the WINTRUST_FILE_INFO structure.
  WINTRUST_FILE_INFO FileData;
  memset(&FileData, 0, sizeof(FileData));

  FileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
  FileData.pcwszFilePath = stringToWstring(path).c_str();
  FileData.hFile = NULL;
  FileData.pgKnownSubject = NULL;

  /*
  WVTPolicyGUID specifies the policy to apply on the file
  WINTRUST_ACTION_GENERIC_VERIFY_V2 policy checks:

  1) The certificate used to sign the file chains up to a root
  certificate located in the trusted root certificate store. This
  implies that the identity of the publisher has been verified by
  a certification authority.

  2) In cases where user interface is displayed (which this example
  does not do), WinVerifyTrust will check for whether the
  end entity certificate is stored in the trusted publisher store,
  implying that the user trusts content from this publisher.

  3) The end entity certificate has sufficient permission to sign
  code, as indicated by the presence of a code signing EKU or no
  EKU.
  */

  GUID WVTPolicyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
  WINTRUST_DATA WinTrustData;

  // Initialize the WinVerifyTrust input data structure.

  // Default all fields to 0.
  memset(&WinTrustData, 0, sizeof(WinTrustData));

  WinTrustData.cbStruct = sizeof(WinTrustData);

  // Use default code signing EKU.
  WinTrustData.pPolicyCallbackData = nullptr;

  // No data to pass to SIP.
  WinTrustData.pSIPClientData = nullptr;

  // Disable WVT UI.
  WinTrustData.dwUIChoice = WTD_UI_NONE;

  // No revocation checking.
  WinTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;

  // Verify an embedded signature on a file.
  WinTrustData.dwUnionChoice = WTD_CHOICE_FILE;

  // Verify action.
  WinTrustData.dwStateAction = WTD_STATEACTION_VERIFY;

  // Verification sets this value.
  WinTrustData.hWVTStateData = nullptr;

  // Not used.
  WinTrustData.pwszURLReference = nullptr;

  // This is not applicable if there is no UI because it changes
  // the UI to accommodate running applications instead of
  // installing applications.
  WinTrustData.dwUIContext = 0;

  // Set pFile.
  WinTrustData.pFile = &FileData;

  // WinVerifyTrust verifies signatures as specified by the GUID
  // and Wintrust_Data.
  auto lStatus = WinVerifyTrust(
      nullptr,
      &WVTPolicyGUID,
      &WinTrustData);

  Row r;
  r["path"] = SQL_TEXT(path);
  r["signed"] = lStatus == ERROR_SUCCESS ? INTEGER(1) : INTEGER(0);

/*
        switch (lStatus)
        {
            case ERROR_SUCCESS:
            {
              r["signed"] = 1;
            }
                // Signed file:
                //     - Hash that represents the subject is trusted.
                //
                //     - Trusted publisher without any verification errors.
                //
                //     - UI was disabled in dwUIChoice. No publisher or
                //         time stamp chain errors.
                //
                //     - UI was enabled in dwUIChoice and the user clicked
                //         "Yes" when asked to install and run the signed
                //         subject.
                break;

            case TRUST_E_NOSIGNATURE:
                // The file was not signed or had a signature
                // that was not valid.

                // Get the reason for no signature.
                {
                  r["signed"] = 0;
                }
                dwLastError = GetLastError();
                if (TRUST_E_NOSIGNATURE == dwLastError ||
                        TRUST_E_SUBJECT_FORM_UNKNOWN == dwLastError ||
                        TRUST_E_PROVIDER_UNKNOWN == dwLastError)
                {
                    // The file was not signed.
                    wprintf_s(L"The file \"%s\" is not signed.\n",
                        pwszSourceFile);
                }
                else
                {
                    // The signature was not valid or there was an error
                    // opening the file.
                    wprintf_s(L"An unknown error occurred trying to "
                        L"verify the signature of the \"%s\" file.\n",
                        pwszSourceFile);
                }

                break;

            case TRUST_E_EXPLICIT_DISTRUST:
                // The hash that represents the subject or the publisher
                // is not allowed by the admin or user.
                wprintf_s(L"The signature is present, but specifically "
                    L"disallowed.\n");
                break;

            case TRUST_E_SUBJECT_NOT_TRUSTED:
                // The user clicked "No" when asked to install and run.
                wprintf_s(L"The signature is present, but not "
                    L"trusted.\n");
                break;

            case CRYPT_E_SECURITY_SETTINGS:
                // The hash that represents the subject or the publisher
                // was not explicitly trusted by the admin and the
                // admin policy has disabled user trust. No signature,
                // publisher or time stamp errors.
                wprintf_s(L"CRYPT_E_SECURITY_SETTINGS - The hash "
                    L"representing the subject or the publisher wasn't "
                    L"explicitly trusted by the admin and admin policy "
                    L"has disabled user trust. No signature, publisher "
                    L"or timestamp errors.\n");
                break;

            default:
                // The UI was disabled in dwUIChoice or the admin policy
                // has disabled user trust. lStatus contains the
                // publisher or time stamp chain error.
                wprintf_s(L"Error is: 0x%x.\n",
                    lStatus);
                break;
        }
*/

  // TODO: These fields should either be filled in or modified.
  r["identifier"] = "-1";
  r["cdhash"] = "-1";
  r["team_identifier"] = "-1";
  r["authority"] = "-1";
  results.push_back(r);

  // Any hWVTStateData must be released by a call with close.
  WinTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
  lStatus = WinVerifyTrust(
      NULL,
      &WVTPolicyGUID,
      &WinTrustData);
}

QueryData genSignature(QueryContext& context) {
  QueryData results;

  // The query must provide a predicate with constraints including path or
  // directory. We search for the parsed predicate constraints with the equals
  // operator.
  auto paths = context.constraints["path"].getAll(EQUALS);
  context.expandConstraints(
      "path", LIKE, paths,
      ([&](const std::string& pattern, std::set<std::string>& out) {
        std::vector<std::string> patterns;
        auto status =
            resolveFilePattern(pattern, patterns, GLOB_ALL | GLOB_NO_CANON);
        if (status.ok()) {
          for (const auto& resolved : patterns) {
            out.insert(resolved);
          }
        }
        return status;
      }));
  for (const auto& path_string : paths) {
    // Note: we are explicitly *not* using is_regular_file here, since you can
    // pass a directory path to the verification functions (e.g. for app
    // bundles, etc.)
    if (!pathExists(path_string).ok()) {
      VLOG(1) << "[+] Path did not exist.";
      continue;
    }
    genSignatureForFile(path_string, results);
  }

  return results;
}
}
}
