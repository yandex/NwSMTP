#include "header_parser.h"

header_iterator_range_t::iterator parse_header(header_iterator_range_t header, header_callback_t callback)
{
    typedef header_iterator_range_t::iterator iterator;
    iterator beg = header.begin();
    iterator end = header.end();
    iterator pos = beg;

    while (pos != end)
    {
        register char c = *pos;

        // Check for end of headers (empty line): although RFC-822 recommends
        // to use CRLF for header/body separator (see 4.1 SYNTAX), here, we
        // also check for LF just in case...
        if (c == '\n')
        {
            ++pos;
            break;
        }
        else if (c == '\r' && pos + 1 != end && *(pos + 1) == '\n')
        {
            pos += 2;
            break;
        }

        // This line may be a field description
        if (!isspace(c))
        {
            iterator nameStart = pos;  // remember the start position of the line

            while (pos != end && (*pos != ':' && !isspace(*pos)))
                ++pos;

            iterator nameEnd = pos;

            while (pos != end && isspace(*pos))
                ++pos;

            if (pos == end)
                break;

            if (*pos != ':')
            {
                // Humm...does not seem to be a valid header line.
                // Skip this error and advance to the next line
                pos = nameStart;

                while (pos != end && *pos++ != '\n')
                    ;
            }
            else
            {
                // Extract the field name
                header_iterator_range_t name(nameStart, nameEnd);

                // Skip ':' character
                ++pos;

                // Skip spaces between ':' and the field contents
                while (pos != end && (*pos == ' ' || *pos == '\t'))
                    ++pos;

                iterator ctsStart = pos;
                iterator ctsEnd = pos;

                while (pos != end)
                {
                    ctsEnd = pos;

                    while (pos != end)
                    {
                        c = *pos;

                        // Check for end of line
                        if (c == '\r' && pos + 1 != end && *(pos + 1) == '\n')
                        {
                            ctsEnd = pos;
                            pos += 2;
                            break;
                        }
                        else if (c == '\n')
                        {
                            ctsEnd = pos;
                            ++pos;
                            break;
                        }

                        ++pos;
                    }

                    if (pos == end)
                        break;
                    c = *pos;

                    // Handle the case of folded lines
                    if (c == ' ' || c == '\t')
                    {
                        // This is a folding white-space: we keep it as is and
                        // we continue with contents parsing...
                    }
                    else
                    {
                        // End of this field
                        break;
                    }

                    // Check for end of contents
                    if (c == '\r' && pos + 1 != end && *(pos + 1) == '\n')
                    {
                        pos += 2;
                        break;
                    }
                    else if (c == '\n')
                    {
                        ++pos;
                        break;
                    }
                }

                header_iterator_range_t val(ctsStart, ctsEnd);
                header_iterator_range_t h(nameStart, ctsEnd);

                callback(name, h, val);
            }
        }
        else
        {
            // Skip this error and advance to the next line
            while (pos != end && *pos++ != '\n')
                ;
        }
    }
    return pos;
}
