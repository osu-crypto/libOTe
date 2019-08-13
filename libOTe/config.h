#pragma once


// build the library with simplest OT enabled
/* #undef ENABLE_SIMPLESTOT */

// build the library with Silent OT Extension enabled
#define ENABLE_SILENTOT ON

// Silent OT requires bit poly mul
#ifdef ENABLE_SILENTOT
	#define ENABLE_BITPOLYMUL ON
#endif
