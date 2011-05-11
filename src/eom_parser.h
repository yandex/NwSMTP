#ifndef _EOM_PARSER_H_
#define _EOM_PARSER_H_

#include "envelope.h"
#include <iterator>

// State machine used to find (^|\n).\r?\n (the message end token).
class eom_parser
{
  public:
    eom_parser()
            : state_(STATE_0)
    {}

    template <class Iterator>
    bool parse(Iterator b, Iterator e, Iterator& tok_b, Iterator& tok_e);

    void reset() { state_ = STATE_0; }

  private:
    typedef enum
    {
        STATE_0,     // ^
        STATE_START, // *
        STATE_1,     // ^.
        STATE_2      // ^.\r
    } machine_state_t;
    machine_state_t state_;
};

// State machine used to find \r+\n .
class crlf_parser
{
  public:
    crlf_parser()
            : state_(STATE_START)
    {}

    template <class Iterator>
    bool parse(Iterator b, Iterator e, Iterator& cr, Iterator& tail);

    void reset() { state_ = STATE_START; }

  private:
    typedef enum
    {
        STATE_START, // *
        STATE_1,     // \r+
    } machine_state_t;
    machine_state_t state_;
};

// Finds eom token in [b, e) input range.
/**
 * If the eom token was found:
 * returns true,
 * tok_b: the beginning of the eom token suffix in [b, e) input range
 * tok_e: iterator pointing directly past the last character of the eom token
 *
 * Otherwise:
 * returns false (needs more text)
 * tok_b: the end of the portion of the parsed text that is certain to belong to the message body (ie not includes the prefix of the eom token)
 * tok_e: the end of the text parsed
 *
 * The caller must guarantee that upon the next invocation of this function [tok_b, tok_e) range should still be valid and tok_e-1 = b-1
 */
template <class Iterator>
bool eom_parser::parse(Iterator b, Iterator e, Iterator& tok_b, Iterator& tok_e)
{
    Iterator p=b;
    Iterator s=b;

    for (; p != e; ++p)
    {
        typename std::iterator_traits<Iterator>::value_type ch = *p;
        switch (state_)
        {
            case STATE_0:                  // ^
                if (ch == '.')
                    state_ = STATE_1;     // ^ -> ^.
                else if (ch == '\n')
                    s = p+1;               // ^ -> ^
                else
                    state_ = STATE_START; // ^ -> *
                break;

            case STATE_1:                  // ^.
                if (ch == '\n')
                {
                    tok_e = p+1;
                    tok_b = s;
                    state_ = STATE_0;
                    return true;
                }
                else if (ch == '\r')
                    state_ = STATE_2;     // ^. -> ^.\r
                else
                {                          // need to get rid of '.'
                    state_ = STATE_START; // ^. -> *
                    s = b = p;
                }
                break;

            case STATE_2:                  // ^.\r
                if (ch == '\n')
                {
                    tok_e = p+1;
                    tok_b = s;
                    state_ = STATE_0;
                    return true;
                }
                else                       // ^.\r -> *
                {
                    state_ = STATE_START;
                    b = p;
                }
                break;

            case STATE_START:              // *
                if (ch == '\n')
                {
                    state_ = STATE_0;     // * -> ^
                    s = p+1;
                }
                break;
        }
    }

    tok_b = (state_ == STATE_START ? p : s);
    tok_e = p;
    return false;
}

// Finds \r+\n token in [b, e) input range.
/**
 * If \r+\n was found:
 * returns true,
 * tok_b: the beginning of the \r+\n token suffix in [b, e) input range
 * tok_e: iterator pointing directly past the last character of the found \r+\n token
 *
 * Otherwise:
 * returns false (needs more text)
 * tok_b: the end of the part of the parsed text that does not include the prefix of the \r+\n token
 * tok_e: the end of the text parsed
 *
 * The caller must guarantee that upon the next invocation of this function [tok_b, tok_e) range should still be valid and tok_e-1 = b-1
 */
template <class Iterator>
bool crlf_parser::parse(Iterator b, Iterator e, Iterator& tok_b, Iterator& tok_e)
{
    Iterator p=b;
    Iterator s=b;
    for(; p != e; ++p)
    {
        typename std::iterator_traits<Iterator>::value_type ch = *p;
        switch (state_)
        {
            case STATE_START:                   // *
                if (ch == '\r')
                {
                    s = p;
                    state_ = STATE_1;           // * -> \r+
                }
                break;

            case STATE_1:                       // \r+
                if (ch == '\n')
                {
                    tok_e = p+1;
                    tok_b = s;
                    state_ = STATE_START;
                    return true;
                }
                else if (ch == '\r')            // \r+ -> \r+
                    ;
                else
                    state_ = STATE_START;       // \r+ -> *
                break;
        }
    }

    tok_b = (state_ == STATE_START ? p : s);
    tok_e = p;
    return false;
}

#endif //_EOM_PARSER_H_
