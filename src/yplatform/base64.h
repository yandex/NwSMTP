#ifndef _YPLATFORM_SERVICE_BASE64_H_
#define _YPLATFORM_SERVICE_BASE64_H_

#include <iostream>

namespace yplatform {
namespace service {
namespace base64 {

class decoder_impl
{
  public:

    void init ()
    {
        step_ = step_a;
        plainchar_ = 0;
    }

    int decode_value (char in) const
    {
        static const char decoding[] = {62,-1,-1,-1,63,52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-2,-1,-1,-1,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,-1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51};
        static const char decoding_size = sizeof(decoding);
        in -= 43;
        if (in < 0 || in > decoding_size) return -1;
        return decoding[ static_cast<int> (in) ];
    }

  protected:
    enum decodestep { step_a, step_b, step_c, step_d } step_;
    char plainchar_;
};

class decoder: public decoder_impl
{
  public:

    inline decoder  ()
    {
        init ();
    }

    inline int decode (char ch) const
    {
        return decode_value (ch);
    }

    template <typename IteratorIn, typename IteratorOut>
    IteratorOut
    decode (IteratorIn& fi, IteratorIn const& li,
            IteratorOut& fo, IteratorOut const& lo);

    template <typename IteratorIn, typename IteratorOut>
    IteratorOut
    decode (IteratorIn fi, IteratorIn const& li,
            IteratorOut fo);
};


template <typename IteratorIn, typename IteratorOut>
IteratorOut
decoder::decode (IteratorIn& in_char, IteratorIn const& in_last,
        IteratorOut& out_char, IteratorOut const& out_last)
{
    // typedef typename boost::iterator_value<IteratorIn>::type in_type;
    // typedef typename boost::iterator_value<IteratorOut>::type out_type;

    char fragment;

    switch (step_)
    {
        for (;;)
        {
            case step_a:
                do {
                    if (in_char == in_last)
                        return out_char;

                    fragment = static_cast<char> (decode_value (*in_char++));
                } while (fragment < 0);

                plainchar_ = (fragment & 0x03f) << 2;

            case step_b:
                do {
                    if (in_char == in_last)
                        return out_char;

                    fragment = static_cast<char> (decode_value (*in_char++));
                } while (fragment < 0);

                plainchar_ |= (fragment & 0x030) >> 4; *out_char++ = plainchar_;
                if (out_char == out_last) return out_char;
                plainchar_  = (fragment & 0x00f) << 4;

            case step_c:
                do {
                    if (in_char == in_last)
                        return out_char;

                    fragment = static_cast<char> (decode_value (*in_char++));
                } while (fragment < 0);

                plainchar_ |= (fragment & 0x03c) >> 2; *out_char++ = plainchar_;
                if (out_char == out_last) return out_char;
                plainchar_  = (fragment & 0x003) << 6;

            case step_d:
                do {
                    if (in_char == in_last)
                        return out_char;

                    fragment = static_cast<char> (decode_value (*in_char++));
                } while (fragment < 0);
                plainchar_ |= (fragment & 0x03f);
                *out_char++ = plainchar_;
                if (out_char == out_last) return out_char;
        } // for
    } // switch
}

template <typename IteratorIn, typename IteratorOut>
IteratorOut
decoder::decode (IteratorIn in_char, IteratorIn const& in_last,
        IteratorOut out_char)
{
    // typedef typename boost::iterator_value<IteratorIn>::type in_type;
    // typedef typename boost::iterator_value<IteratorOut>::type out_type;

    char fragment;

    switch (step_)
    {
        for (;;)
        {
            case step_a:
                do {
                    if (in_char == in_last)
                        return out_char;

                    fragment = static_cast<char> (decode_value (*in_char++));
                } while (fragment < 0);

                plainchar_ = (fragment & 0x03f) << 2;

            case step_b:
                do {
                    if (in_char == in_last)
                        return out_char;

                    fragment = static_cast<char> (decode_value (*in_char++));
                } while (fragment < 0);

                plainchar_ |= (fragment & 0x030) >> 4; *out_char++ = plainchar_;
                plainchar_  = (fragment & 0x00f) << 4;

            case step_c:
                do {
                    if (in_char == in_last)
                        return out_char;

                    fragment = static_cast<char> (decode_value (*in_char++));
                } while (fragment < 0);

                plainchar_ |= (fragment & 0x03c) >> 2; *out_char++ = plainchar_;
                plainchar_  = (fragment & 0x003) << 6;

            case step_d:
                do {
                    if (in_char == in_last)
                        return out_char;

                    fragment = static_cast<char> (decode_value (*in_char++));
                } while (fragment < 0);
                plainchar_ |= (fragment & 0x03f);
                *out_char++ = plainchar_;
        } // for
    } // switch

    // really can never be here
    return out_char;
}

}}}

#endif // _YPLATFORM_SERVICE_BASE64_H_
