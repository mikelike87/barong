# frozen_string_literal: true

require 'spec_helper'

describe '/api/v2/auth functionality test' do
  let!(:email) { 'user@gmail.com' }
  let!(:password) { 'RandomPass1339' }
  let(:uri) { '/api/v2/identity/sessions' }
  let(:params) do
    {
      email: email,
      password: password
    }
  end
  subject!(:user) do
    create :user,
           email: email,
           password: password,
           password_confirmation: password
  end
  let(:do_create_session_request) { post uri, params: params }
  let(:auth_request) { '/api/v2/auth/not_in_the_rules_path' }
  let(:protected_request) { '/api/v2/resource/users/me' }

  context 'testing workability with valid session' do
    before do
      do_create_session_request
    end

    it 'returns bearer token on valid session' do
      get auth_request
      expect(response.status).to eq(200)
      expect(response.headers['Authorization']).not_to be_nil
      expect(response.headers['Authorization']).to include "Bearer"
    end

    it 'allows any type of request' do
      available_types = %w[post get put head delete patch]
      available_types.each do |ping|
        method("#{ping}").call auth_request
        expect(response.headers['Authorization']).not_to be_nil

        get protected_request, headers: { 'Authorization' => response.headers['Authorization'] }
        expect(response.status).to eq(200)
      end
    end
  end

  context 'testing errors and restrictions' do
    it 'renders error if no session or api key headers provided' do
      get auth_request
      expect(response.status).to eq(401)
      expect(response.body).to eq("{\"error\":\"Invalid Session\"}")
    end

    it 'renders error if session belongs to non-active user' do
      do_create_session_request
      expect(response.status).to eq(200)
      user.update(state: 'banned')

      get auth_request
      expect(response.status).to eq(401)
      expect(response.body).to eq("{\"error\":\"User account is not active!\"}")
    end

    let(:do_restricted_request) { put '/api/v2/auth/api/v2/peatio/blocked/ping' }

    it 'receives access error if path is blacklisted' do
      do_create_session_request
      expect(response.status).to eq(200)

      do_restricted_request
      expect(response.status).to eq(401)
      expect(response.body).to eq("{\"error\":\"permission_denied\"}")
    end

    let(:two_times_underlured_path_request) { put '/api/v2/auth/api/v2/barong/both-listed/ping' }

    it 'receives access error if path is blacklisted and whitelisted (blacklisting is a priority)' do
      do_create_session_request
      expect(response.status).to eq(200)

      two_times_underlured_path_request
      expect(response.status).to eq(401)
      expect(response.body).to eq("{\"error\":\"permission_denied\"}")
    end

    let(:do_whitelisted_request) { put '/api/v2/auth/api/v2/peatio/public/ping' }

    it 'receives access error if path is blacklisted' do
      do_create_session_request
      expect(response.status).to eq(200)

      do_whitelisted_request
      expect(response.status).to eq(200)
      expect(response.body).to be_empty
      expect(response.headers['Authorization']).to be_nil
    end
  end
end
