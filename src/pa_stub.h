#if defined(HAVE_CONFIG_H)

    #include "../config.h"
    
    #if defined(HAVE_PA_INTERFACE_H)
	
	#define HAVE_PA
    #else
    
	#undef HAVE_PA
    
    #endif
#else

    #undef HAVE_PA
    
#endif
