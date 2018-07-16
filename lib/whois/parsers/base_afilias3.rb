#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2018 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base'
require 'whois/scanners/base_afilias'


module Whois
  class Parsers

    # Base parser for Afilias servers.
    #
    # @abstract
    class BaseAfilias3 < Base
      include Scanners::Scannable

      self.scanner = Scanners::BaseAfilias


      property_supported :disclaimer do
        node("field:disclaimer")
      end


      property_supported :domain do
        node("Domain Name", &:downcase)
      end

      property_supported :domain_id do
        node("Registry Domain ID")
      end

      property_supported :status do
        if reserved?
          :reserved
        else
          Array.wrap(node("Domain Status"))
        end
      end

      property_supported :available? do
        !!node("status:available")
      end

      property_supported :registered? do
        !available?
      end


      property_supported :created_on do
        node("Creation Date") do |value|
          parse_time(value)
        end
      end

      property_supported :updated_on do
        node("Updated Date") do |value|
          parse_time(value)
        end
      end

      property_supported :expires_on do
        node("Registry Expiry Date") do |value|
          parse_time(value)
        end
      end


      property_supported :registrar do
        node('Registrar') do |name|
          Parser::Registrar.new(
              id:           node('Registrar IANA ID'),
              name:         node('Registrar'),
              organization: node('Registrar'),
              url:          node('Registrar URL')
          )
        end
      end

      property_supported :registrant_contacts do
        build_contact("Registrant", Parser::Contact::TYPE_REGISTRANT)
      end

      property_supported :admin_contacts do
        build_contact("Admin", Parser::Contact::TYPE_ADMINISTRATIVE)
      end

      property_supported :technical_contacts do
        build_contact("Tech", Parser::Contact::TYPE_TECHNICAL)
      end


      property_supported :nameservers do
        Array.wrap(node("Name Server")).reject(&:empty?).map do |name|
          Parser::Nameserver.new(:name => name.downcase)
        end
      end


      private

      def build_contact(element, type)
        node("Registry #{element} ID") do
          address = ["", "1", "2", "3"].
              map { |i| node("#{element} Street#{i}") }.
              delete_if { |i| i.nil? || i.empty? }.
              join("\n")

          Parser::Contact.new(
              :type         => type,
              :id           => node("#{element} ID"),
              :name         => node("#{element} Name"),
              :organization => node("#{element} Organization"),
              :address      => address,
              :city         => node("#{element} City"),
              :zip          => node("#{element} Postal Code"),
              :state        => node("#{element} State/Province"),
              :country_code => node("#{element} Country"),
              :phone        => node("#{element} Phone"),
              :fax          => node("#{element} FAX") || node("#{element} Fax"),
              :email        => node("#{element} Email")
          )
        end
      end

      def decompose_registrar(value)
        if value =~ /(.+?) \((.+?)\)/
          [$2, $1]
        else
          [nil, value]
        end
      end

    end

  end
end
