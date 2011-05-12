#include <config.h>

#ifdef ENABLE_AUTH_BLACKBOX

#include <vector>
#include <boost/bind.hpp>
#include <sstream>
#include <iostream>
#include <fstream>
#include <boost/type_traits.hpp>
#include <boost/format.hpp>
#include <boost/bind/protect.hpp>
#include <algorithm>

#include "smtp_connection.h"
#include "smtp_connection_manager.h"
#include "log.h"
#include "options.h"
#include "uti.h"
#include "ip_options.h"

void smtp_connection::handle_bb_mailfrom_helper(check::chk_status _status, black_box_client_mailfrom::mailfrom_result_t _result)
{
    m_proto_state = STATE_HELLO;

    m_envelope->karma_ = _result.karma_;
    m_envelope->karma_status_ = _result.karma_status_;
    m_envelope->time_stamp_ = _result.time_stamp_;		// born data
    m_envelope->auth_mailfrom_ = true;

    if (authenticated_ && m_suid)
    {
	if (m_suid != _result.suid_)
	{
	    _status = check::CHK_REJECT;
	}
    }

    switch (_status)
    {
        case check::CHK_ACCEPT:
            authenticated_ = true;

            end_mail_from_command(false, true, _result.auth_addr_, "");

            break;

        case check::CHK_DISCARD:
        case check::CHK_REJECT:

            end_mail_from_command(false, true, _result.auth_addr_, "553 5.7.1 Sender address rejected: not owned by auth user.");

            break;

        case check::CHK_TEMPFAIL:

            end_mail_from_command(false, true, _result.auth_addr_, "454 4.3.0 Try again later");

            break;
    }

}


void smtp_connection::handle_bb_mailfrom_result(check::chk_status _check, black_box_client_mailfrom::mailfrom_result_t _result)
{
    if (!m_bb_check_mailfrom)
        return;

    if (m_bb_check_mailfrom)
        m_bb_check_mailfrom->stop();

    m_bb_check_mailfrom.reset();

    handle_bb_mailfrom_helper(_check, _result);
}

#endif // ENABLE_AUTH_BLACKBOX
