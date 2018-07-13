#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2018 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base_afilias3'
require 'whois/scanners/whois.afilias.net.rb'

module Whois
  class Parsers

    # Parser for the whois.afilias.net server.
    class WhoisAfiliasNet < BaseAfilias3

      self.scanner = Scanners::WhoisAfiliasNet, {
          pattern_reserved: /^(Name is reserved by afilias\n)|(Reserved by Registry\n)/,
      }

      # NEWPROPERTY
      def reserved?
        !!node("status:reserved")
      end

    end

  end
end
