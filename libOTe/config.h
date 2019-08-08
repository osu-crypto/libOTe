#pragma once


// build the library with simplest OT enabled
#define ENABLE_SIMPLESTOT ON


// build the library with Silent OT Extension enabled
#define ENABLE_SILENT_OT ON

// Silent OT requires bit poly mul
#define ENABLE_BITPOLYMUL ENABLE_SILENT_OT
