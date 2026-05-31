#pragma once

#include <Windows.h>

// __TIME__ format is always: "HH:MM:SS"
//
// Example:
// If compiled at 14:37:52
//
// __TIME__[0] = '1'   // first digit of hour (tens place)
// __TIME__[1] = '4'   // second digit of hour (ones place)
// __TIME__[2] = ':'   // separator
// __TIME__[3] = '3'   // first digit of minutes (tens place)
// __TIME__[4] = '7'   // second digit of minutes (ones place)
// __TIME__[5] = ':'   // separator
// __TIME__[6] = '5'   // first digit of seconds (tens place)
// __TIME__[7] = '2'   // second digit of seconds (ones place)

constexpr ULONG RandomCompileTimeSeed(void) {
	return
		(__TIME__[7] - '0') +
		(__TIME__[6] - '0') * 10 +
		(__TIME__[4] - '0') * 60 +
		(__TIME__[3] - '0') * 600 +
		(__TIME__[1] - '0') * 3600 +
		(__TIME__[0] - '0') * 36000;
}

constexpr ULONG g_InitHash = RandomCompileTimeSeed();

constexpr ULONG HashStringFowlerNollVoVariant1aA(IN LPCSTR String)
{
	ULONG Hash = g_InitHash;

	while (*String)
	{
		UCHAR c = *String++;
		if (c >= 'A' && c <= 'Z')
			Hash ^= c + 0x20;
		else
			Hash ^= c;
		Hash *= 0x01000193;
	}

	return Hash;
}

constexpr ULONG HashStringFowlerNollVoVariant1aW(IN LPCWSTR String)
{
	ULONG Hash = g_InitHash;

	while (*String)
	{
		UCHAR c = *String++;
		if (c >= L'A' && c <= L'Z')
			Hash ^= c + 0x20;
		else
			Hash ^= c;
		Hash *= 0x01000193;
	}

	return Hash;
}

// Compile-time macros to define the hash values for WinAPI functions
// It defines variables at compile time with the format:
//			constexpr auto WinApiFuncName_FnvvA/W = HashValue
#define CTIME_HFOWLERA(API) constexpr auto API##_FnvvA = HashStringFowlerNollVoVariant1aA((LPCSTR) #API);
#define CTIME_HFOWLERW(API) constexpr auto API##_FnvvW = HashStringFowlerNollVoVariant1aW((LPCWSTR) L#API);

// Runtime macros to call respective hash function during WinAPI resolution
#define	RTIME_HFOWLERA(API) HashStringFowlerNollVoVariant1aA((LPCSTR)API)
#define RTIME_HFOWLERW(API) HashStringFowlerNollVoVariant1aW((LPCWSTR)API)