#ifndef _EOM_PARSER_H_
#define _EOM_PARSER_H_

#include "envelope.h"

class eom_parser
{
  public:
    eom_parser();       

    bool parse(const char* b, const char* e, const char*& eom, const char*& tail);

    void reset();
        
  private:    
    typedef enum    
    {
        STATE_0,     // ^
        STATE_START, // *
        STATE_1,     // ^.
        STATE_2      // ^.\r
    } machine_state_t;
    machine_state_t m_state;
};

#endif //_EOM_PARSER_H_
