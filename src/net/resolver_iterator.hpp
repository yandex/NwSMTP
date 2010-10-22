#ifndef RESOLVER_ITERATOR_H
#define RESOLVER_ITERATOR_H

#include <boost/iterator/iterator_facade.hpp>
#include <boost/optional.hpp>
#include <boost/shared_ptr.hpp>
#include <net/dns.hpp>

namespace y {
namespace net {
namespace dns {

class resolver_iterator
        : public boost::iterator_facade<
    resolver_iterator,
    const shared_resource_base_t,
    boost::forward_traversal_tag>
{
  public:
    resolver_iterator()
    {
    }

    static resolver_iterator create(
        const rr_list_t& l,
        type_t t)
    {
        resolver_iterator iter;
        if (l.empty())
            return iter;

        iter.values_.reset(new values_type);

        for (rr_list_t::const_iterator it=l.begin(); it!=l.end(); ++it)
        {
            if ((*it)->rtype() == t)        
                iter.values_->push_back(*it);       
        }
        
        if (iter.values_->size())
            iter.iter_ = iter.values_->begin();
        else
            iter.values_.reset();

        return iter;
    }

    static resolver_iterator create(
        shared_resource_base_t r)
    {
        resolver_iterator iter;

        if (r)
        {
            iter.values_.reset(new values_type);
            iter.values_->push_back(r);
            iter.iter_ = iter.values_->begin();
        }

        return iter;
    }


  private:
    friend class boost::iterator_core_access;
    
    void increment()
    {
        if (++*iter_ == values_->end())
        {
            // Reset state to match a default constructed end iterator.
            values_.reset();
            iter_.reset();
        }
    }

    bool equal(const resolver_iterator& other) const
    {
        if (!values_ && !other.values_)
            return true;
        if (values_ != other.values_)
            return false;
        return *iter_ == *other.iter_;
    }

    const shared_resource_base_t& dereference() const
    {
        return **iter_;
    }

    typedef rr_list_t values_type;
    typedef rr_list_t::const_iterator values_iter_type;
    boost::shared_ptr<values_type> values_;
    boost::optional<values_iter_type> iter_;
};

} // namespace y
} // namespace net
} // namespace dns

#endif //RESOLVER_ITERATOR_H

