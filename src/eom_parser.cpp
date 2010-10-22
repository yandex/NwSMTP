#include "eom_parser.h"


eom_parser::eom_parser()
{
    m_state = STATE_0;
}

void eom_parser::reset()
{
    m_state = STATE_0;
}

/*
  If the end of the message was found:
  returns true, 
  eom,
  tail - the left over portion of the text directly past the parsed message

  Otherwise:
  returns false 
  (needs more text)
*/
bool eom_parser::parse(const char* b, const char* e, const char*& eom, const char*& tail)
{      
    const char* p=b;
    const char* s=b;

    for (; p != e; ++p)
    {
        register char ch = *p;
        switch (m_state)
        {
            case STATE_0:                  // ^
                if (ch == '.')
                    m_state = STATE_1;     // ^ -> ^.
                else if (ch == '\n')        
                    s = p+1;               // ^ -> ^       
                else
                    m_state = STATE_START; // ^ -> * 
                break;

            case STATE_1:                  // ^.
                if (ch == '\n')            
                {
                    //          message.write(b, s);
                    tail = p+1;
                    eom = s;
                    //tail = string(p+1, e);
                    m_state = STATE_0;
                    return true;                
                } 
                else if (ch == '\r')                
                    m_state = STATE_2;     // ^. -> ^.\r                
                else                       
                {                          // need to get rid of '.' 
                    m_state = STATE_START; // ^. -> *
                    //                message.write(b, s);              
                    s = b = p;          
                }   
                break;

            case STATE_2:                  // ^.\r
                if (ch == '\n')
                {
                    //          message.write(b, s);
                    tail = p+1;
                    eom = s;
                    //tail = string(p+1, e);
                    m_state = STATE_0;
                    return true;                
                }           
                else                       // ^.\r -> *     
                {
                    m_state = STATE_START;
                    //                const char* str = ".\r";
                    //          message.write(str, str+2);
                    b = p;
                }
                break;

            case STATE_START:              // *
                if (ch == '\n')
                {
                    m_state = STATE_0;     // * -> ^
                    s = p+1;            
                }
                break;
        }
    }
  
    //    message.write(b, (m_state == STATE_START ? p : s) );
    eom = (m_state == STATE_START ? p : s);
    return false;
}
