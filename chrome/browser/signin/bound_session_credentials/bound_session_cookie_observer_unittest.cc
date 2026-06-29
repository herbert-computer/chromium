// Copyright 2023 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/signin/bound_session_credentials/bound_session_cookie_observer.h"

#include <cstddef>
#include <memory>

#include "base/barrier_callback.h"
#include "base/functional/bind.h"
#include "base/functional/callback.h"
#include "base/functional/callback_helpers.h"
#include "base/test/task_environment.h"
#include "base/test/test_future.h"
#include "base/time/time.h"
#include "chrome/browser/signin/bound_session_credentials/bound_session_test_cookie_manager.h"
#include "content/public/test/test_storage_partition.h"
#include "mojo/public/cpp/bindings/remote.h"
#include "net/cookies/canonical_cookie.h"
#include "net/cookies/cookie_access_result.h"
#include "net/cookies/cookie_change_dispatcher.h"
#include "net/cookies/cookie_inclusion_status.h"
#include "net/cookies/cookie_options.h"
#include "services/network/cookie_manager.h"
#include "services/network/network_context.h"
#include "services/network/network_service.h"
#include "services/network/public/mojom/cookie_manager.mojom.h"
#include "services/network/public/mojom/network_context.mojom.h"
#include "services/network/test/fake_test_cert_verifier_params_factory.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"

#include "base/run_loop.h"
#include "base/test/bind.h"
#include "nova/base/http_client/http_client.h"
#include "services/network/public/cpp/weak_wrapper_shared_url_loader_factory.h"
#include "services/network/public/cpp/originating_process_id.h"
#include "net/dns/mock_host_resolver.h"

namespace {
constexpr char kSIDTSCookieName[] = "__Secure-1PSIDTS";

class HostResolverFactory final : public net::HostResolver::Factory {
 public:
  explicit HostResolverFactory(std::unique_ptr<net::HostResolver> resolver)
      : resolver_(std::move(resolver)) {}

  std::unique_ptr<net::HostResolver> CreateResolver(
      net::HostResolverManager* manager,
      std::string_view host_mapping_rules,
      bool enable_caching,
      bool enable_stale) override {
    DCHECK(resolver_);
    return std::move(resolver_);
  }

  // See HostResolver::CreateStandaloneResolver.
  std::unique_ptr<net::HostResolver> CreateStandaloneResolver(
      net::NetLog* net_log,
      const net::HostResolver::ManagerOptions& options,
      std::string_view host_mapping_rules,
      bool enable_caching,
      bool enable_stale) override {
    NOTREACHED();
  }

 private:
  std::unique_ptr<net::HostResolver> resolver_;
};

class CookieChangeListener : public network::mojom::CookieChangeListener {
 public:
  CookieChangeListener(
      network::CookieManager* cookie_manager,
      const GURL& url,
      base::RepeatingCallback<void(const net::CookieChangeInfo&)> callback)
      : callback_(std::move(callback)), receiver_(this) {
    cookie_manager->AddCookieChangeListener(
        url, std::nullopt, receiver_.BindNewPipeAndPassRemote());
  }

  // network::mojom::CookieChangeListener:
  void OnCookieChange(const net::CookieChangeInfo& change) override {
    callback_.Run(change);
  }

 private:
  base::RepeatingCallback<void(const net::CookieChangeInfo&)> callback_;
  mojo::Receiver<network::mojom::CookieChangeListener> receiver_;
};

class BoundSessionCookieObserverTest : public testing::Test {
 public:
  const GURL kGoogleUrl = GURL("https://google.com");
  const GURL kGaiaUrl = GURL("https://accounts.google.com");
  BoundSessionCookieObserverTest()
      : network_service_(network::NetworkService::CreateForTesting()) {
    ResetCookieManager();
  }

  ~BoundSessionCookieObserverTest() override = default;

  void CreateObserver(const GURL& url) {
    CHECK(!bound_session_cookie_observer_)
        << "Call Reset() before creating a new observer.";

    bound_session_cookie_observer_ =
        std::make_unique<BoundSessionCookieObserver>(
            &storage_partition_, url, kSIDTSCookieName,
            base::BindRepeating(
                &BoundSessionCookieObserverTest::UpdateExpirationDate,
                base::Unretained(this)));
  }

  void ResetCookieManager() {
    auto context_params = network::mojom::NetworkContextParams::New();
    // Use a dummy CertVerifier that always passes cert verification, since
    // these unittests don't need to test CertVerifier behavior.
    context_params->cert_verifier_params =
        network::FakeTestCertVerifierParamsFactory::GetCertVerifierParams();
    
    network_context_remote_.reset();

    auto resolver = std::make_unique<net::MockHostResolver>();
  resolver->rules()->AddRule("example.com", "172.66.0.243");
  network_service_->set_host_resolver_factory_for_testing(
      std::make_unique<HostResolverFactory>(std::move(resolver)));

    auto network_context = network::NetworkContext::CreateForTesting(
        network_service_.get(),
        network_context_remote_.BindNewPipeAndPassReceiver(),
        std::move(context_params), base::DoNothing());
    storage_partition_.set_cookie_manager_for_browser_process(
        network_context->cookie_manager());
    // Reset storage partition's cookie manager before resetting
    // `network_context_` to avoid having a dangling raw pointer.
    network_context_ = std::move(network_context);

    network::mojom::URLLoaderFactoryParamsPtr params =
        network::mojom::URLLoaderFactoryParams::New();
    params->process_id = network::OriginatingProcessId::browser();
    // params->is_orb_enabled = false;
    network_context_->CreateURLLoaderFactory(
        loader_factory_.BindNewPipeAndPassReceiver(), std::move(params));
    shared_url_loader_factory_ =
        base::MakeRefCounted<network::WeakWrapperSharedURLLoaderFactory>(
            loader_factory_.get());
  }

  void Reset() {
    bound_session_cookie_observer_.reset();
    on_cookie_change_callback_.Reset();
    update_expiration_date_call_count_ = 0;
    cookie_expiration_date_ = base::Time();
  }

  void SetNextCookieChangeCallback(
      base::OnceCallback<void(const std::string&, base::Time)> callback) {
    // Old expectations should have been verified.
    EXPECT_FALSE(on_cookie_change_callback_);
    on_cookie_change_callback_ = std::move(callback);
  }

  void UpdateExpirationDate(const std::string& cookie_name,
                            base::Time expiration_date) {
    update_expiration_date_call_count_++;
    cookie_expiration_date_ = expiration_date;
    if (on_cookie_change_callback_) {
      std::move(on_cookie_change_callback_).Run(cookie_name, expiration_date);
    }
  }

  void RunCookieInsertWasObservedTest(const GURL& observer_url,
                                      const GURL& cookie_url) {
    CreateObserver(observer_url);
    update_expiration_date_call_count_ = 0;

    net::CanonicalCookie cookie = BoundSessionTestCookieManager::CreateCookie(
        cookie_url, kSIDTSCookieName);
    base::test::TestFuture<const std::string&, base::Time> future;
    SetNextCookieChangeCallback(future.GetCallback());
    cookie_manager()->SetCanonicalCookie(cookie, cookie_url,
                                         net::CookieOptions::MakeAllInclusive(),
                                         base::DoNothing());

    EXPECT_EQ(future.Get<0>(), cookie.Name());
    EXPECT_EQ(future.Get<1>(), cookie.ExpiryDate());
    EXPECT_EQ(update_expiration_date_call_count_, 1u);
    EXPECT_EQ(cookie_expiration_date_, cookie.ExpiryDate());
  }

  void RunCookieInsertWasNotObservedTest(const GURL& observer_url,
                                         const GURL& cookie_url) {
    CreateObserver(observer_url);
    update_expiration_date_call_count_ = 0;

    base::test::TestFuture<const net::CookieChangeInfo&> future;
    // `listener` should be notified about the cookie change, unlike the
    // observer.
    CookieChangeListener listener(cookie_manager(), cookie_url,
                                  future.GetRepeatingCallback());
    cookie_manager()->SetCanonicalCookie(
        BoundSessionTestCookieManager::CreateCookie(cookie_url,
                                                    kSIDTSCookieName),
        cookie_url, net::CookieOptions::MakeAllInclusive(), base::DoNothing());

    // It's important that the test waits until the cookie update is dispatched
    // to CookieChangeListeners.
    ASSERT_TRUE(future.Wait());
    EXPECT_EQ(update_expiration_date_call_count_, 0u);
  }

  network::CookieManager* cookie_manager() {
    return network_context_->cookie_manager();
  }

 protected:
  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::TimeSource::MOCK_TIME,
    base::test::TaskEnvironment::MainThreadType::IO};
  std::unique_ptr<network::NetworkService> network_service_;
  std::unique_ptr<network::NetworkContext> network_context_;
  mojo::Remote<network::mojom::NetworkContext> network_context_remote_;
  content::TestStoragePartition storage_partition_;

  std::unique_ptr<BoundSessionCookieObserver> bound_session_cookie_observer_;
  size_t update_expiration_date_call_count_ = 0;
  base::Time cookie_expiration_date_;
  base::OnceCallback<void(const std::string&, base::Time)>
      on_cookie_change_callback_;

  std::unique_ptr<nova::HttpClient> http_client_;

  scoped_refptr<network::SharedURLLoaderFactory> shared_url_loader_factory_;
  mojo::Remote<network::mojom::URLLoaderFactory> loader_factory_;
};

TEST_F(BoundSessionCookieObserverTest, CookieAvailableOnStartup) {
  // Set Cookie.
  net::CanonicalCookie cookie =
      BoundSessionTestCookieManager::CreateCookie(kGoogleUrl, kSIDTSCookieName);
  cookie_manager()->SetCanonicalCookie(cookie, kGoogleUrl,
                                       net::CookieOptions::MakeAllInclusive(),
                                       base::DoNothing());

  CreateObserver(kGoogleUrl);
  EXPECT_EQ(update_expiration_date_call_count_, 1u);
  EXPECT_EQ(cookie_expiration_date_, cookie.ExpiryDate());
}

TEST_F(BoundSessionCookieObserverTest, CookieMissingOnStartup) {
  CreateObserver(kGoogleUrl);

  EXPECT_EQ(update_expiration_date_call_count_, 1u);
  EXPECT_EQ(cookie_expiration_date_, base::Time());
}

TEST_F(BoundSessionCookieObserverTest, CookieInserted) {
  RunCookieInsertWasObservedTest(kGoogleUrl, kGoogleUrl);
}

TEST_F(BoundSessionCookieObserverTest, CookieInsertedOnDifferentSite) {
  RunCookieInsertWasNotObservedTest(kGoogleUrl, GURL("https://youtube.com"));
}

TEST_F(BoundSessionCookieObserverTest, CookieInsertedOnDomain) {
  RunCookieInsertWasObservedTest(kGaiaUrl, kGaiaUrl);
}

TEST_F(BoundSessionCookieObserverTest, CookieInsertedOnParentDomain) {
  RunCookieInsertWasObservedTest(kGaiaUrl, kGoogleUrl);
}

TEST_F(BoundSessionCookieObserverTest, CookieInsertedOnSubdomain) {
  RunCookieInsertWasNotObservedTest(kGoogleUrl, kGaiaUrl);
}

TEST_F(BoundSessionCookieObserverTest, CookieInsertedOnDifferentSubdomain) {
  RunCookieInsertWasNotObservedTest(kGaiaUrl, GURL("https://docs.google.com"));
}

TEST_F(BoundSessionCookieObserverTest, CookieInsertedOnPath) {
  RunCookieInsertWasObservedTest(kGoogleUrl.Resolve("/path"),
                                 kGoogleUrl.Resolve("/path"));
}

TEST_F(BoundSessionCookieObserverTest, CookieInsertedOnParentPath) {
  RunCookieInsertWasObservedTest(kGoogleUrl.Resolve("/path"), kGoogleUrl);
}

TEST_F(BoundSessionCookieObserverTest, CookieInsertedOnSubPath) {
  RunCookieInsertWasNotObservedTest(kGoogleUrl, kGoogleUrl.Resolve("/path"));
}

TEST_F(BoundSessionCookieObserverTest, CookieInsertedOnDifferentPath) {
  RunCookieInsertWasNotObservedTest(kGoogleUrl.Resolve("/path"),
                                    kGoogleUrl.Resolve("/other_path"));
}

TEST_F(BoundSessionCookieObserverTest,
       CookieOverwriteDoesNotTriggerANotification) {
  net::CanonicalCookie cookie = BoundSessionTestCookieManager::CreateCookie(
      kGoogleUrl, kSIDTSCookieName, base::Time::Now() + base::Minutes(10));
  cookie_manager()->SetCanonicalCookie(cookie, kGoogleUrl,
                                       net::CookieOptions::MakeAllInclusive(),
                                       base::DoNothing());
  CreateObserver(kGoogleUrl);
  update_expiration_date_call_count_ = 0;

  // No notification should be fired for `net::CookieChangeCause::OVERWRITE`.
  base::Time new_expiry_date = cookie.ExpiryDate() + base::Minutes(10);
  net::CanonicalCookie cookie_update =
      BoundSessionTestCookieManager::CreateCookie(kGoogleUrl, kSIDTSCookieName,
                                                  new_expiry_date);
  base::test::TestFuture<std::vector<net::CookieChangeInfo>> future;
  CookieChangeListener listener(
      cookie_manager(), kGoogleUrl,
      base::BarrierCallback<const net::CookieChangeInfo&>(
          /*num_callbacks=*/2, future.GetRepeatingCallback()));
  cookie_manager()->SetCanonicalCookie(cookie_update, kGoogleUrl,
                                       net::CookieOptions::MakeAllInclusive(),
                                       base::DoNothing());
  // Replacing an existing cookie is actually a two-phase delete + set
  // operation, so `listener` gets an extra notification.
  EXPECT_THAT(
      future.Get(),
      testing::UnorderedElementsAre(
          testing::Field("cause", &net::CookieChangeInfo::cause,
                         net::CookieChangeCause::OVERWRITE),
          testing::Field(
              "cause", &net::CookieChangeInfo::cause,
              net::CookieChangeCause::INSERTED_NO_VALUE_CHANGE_OVERWRITE)));

  EXPECT_EQ(update_expiration_date_call_count_, 1u);
  EXPECT_EQ(cookie_expiration_date_, new_expiry_date);
}

TEST_F(BoundSessionCookieObserverTest, CookieDeletedExplicit) {
  net::CanonicalCookie cookie =
      BoundSessionTestCookieManager::CreateCookie(kGoogleUrl, kSIDTSCookieName);
  cookie_manager()->SetCanonicalCookie(cookie, kGoogleUrl,
                                       net::CookieOptions::MakeAllInclusive(),
                                       base::DoNothing());
  CreateObserver(kGoogleUrl);
  update_expiration_date_call_count_ = 0;

  base::test::TestFuture<const std::string&, base::Time> future;
  SetNextCookieChangeCallback(future.GetCallback());
  cookie_manager()->DeleteCanonicalCookie(cookie, base::DoNothing());

  EXPECT_EQ(future.Get<0>(), cookie.Name());
  EXPECT_EQ(future.Get<1>(), base::Time());
  EXPECT_EQ(update_expiration_date_call_count_, 1u);
  EXPECT_EQ(cookie_expiration_date_, base::Time());
}

TEST_F(BoundSessionCookieObserverTest, CookieExpiredOverwrite) {
  net::CanonicalCookie cookie =
      BoundSessionTestCookieManager::CreateCookie(kGoogleUrl, kSIDTSCookieName);
  cookie_manager()->SetCanonicalCookie(cookie, kGoogleUrl,
                                       net::CookieOptions::MakeAllInclusive(),
                                       base::DoNothing());
  CreateObserver(kGoogleUrl);
  update_expiration_date_call_count_ = 0;

  net::CanonicalCookie cookie_update =
      BoundSessionTestCookieManager::CreateCookie(
          kGoogleUrl, kSIDTSCookieName, base::Time::Now() - base::Minutes(1));
  base::test::TestFuture<const std::string&, base::Time> future;
  SetNextCookieChangeCallback(future.GetCallback());
  cookie_manager()->SetCanonicalCookie(cookie_update, kGoogleUrl,
                                       net::CookieOptions::MakeAllInclusive(),
                                       base::DoNothing());

  EXPECT_EQ(future.Get<0>(), cookie.Name());
  EXPECT_EQ(future.Get<1>(), base::Time());
  EXPECT_EQ(update_expiration_date_call_count_, 1u);
  EXPECT_EQ(cookie_expiration_date_, base::Time());
}

TEST_F(BoundSessionCookieObserverTest, CookieExpired) {
  net::CanonicalCookie cookie = BoundSessionTestCookieManager::CreateCookie(
      kGoogleUrl, kSIDTSCookieName, base::Time::Now() + base::Minutes(10));
  cookie_manager()->SetCanonicalCookie(cookie, kGoogleUrl,
                                       net::CookieOptions::MakeAllInclusive(),
                                       base::DoNothing());
  CreateObserver(kGoogleUrl);
  update_expiration_date_call_count_ = 0;

  base::test::TestFuture<const std::string&, base::Time> future;
  SetNextCookieChangeCallback(future.GetCallback());
  task_environment_.FastForwardBy(cookie.ExpiryDate() - base::Time::Now() +
                                  base::Seconds(5));
  // Request all cookies to trigger garbage collection of expired cookies.
  cookie_manager()->GetAllCookies(base::DoNothing());

  EXPECT_EQ(future.Get<0>(), cookie.Name());
  EXPECT_EQ(future.Get<1>(), cookie.ExpiryDate());
  EXPECT_EQ(update_expiration_date_call_count_, 1u);
  EXPECT_EQ(cookie_expiration_date_, cookie.ExpiryDate());
}

TEST_F(BoundSessionCookieObserverTest, OnCookieChangeListenerConnectionError) {
  // Set cookie.
  net::CanonicalCookie cookie =
      BoundSessionTestCookieManager::CreateCookie(kGoogleUrl, kSIDTSCookieName);
  cookie_manager()->SetCanonicalCookie(cookie, kGoogleUrl,
                                       net::CookieOptions::MakeAllInclusive(),
                                       base::DoNothing());
  CreateObserver(kGoogleUrl);
  EXPECT_EQ(update_expiration_date_call_count_, 1u);
  EXPECT_EQ(cookie_expiration_date_, cookie.ExpiryDate());

  base::test::TestFuture<const std::string&, base::Time> future_removed;
  SetNextCookieChangeCallback(future_removed.GetCallback());

  // Reset the cookie manager to simulate
  // `OnCookieChangeListenerConnectionError`.
  // The new `cookie_manager()` doesn't have the cookie, it is expected to
  // trigger a notification that the cookie has been removed.
  ResetCookieManager();

  // Expect a notification that the cookie was removed.
  EXPECT_EQ(future_removed.Get<1>(), base::Time());
  EXPECT_EQ(update_expiration_date_call_count_, 2u);
  EXPECT_EQ(cookie_expiration_date_, base::Time());

  // Trigger a cookie change to verify the cookie listener has been hooked up
  // to the new `cookie_manager()`.
  // Insert event.
  base::test::TestFuture<const std::string&, base::Time> future_inserted;
  SetNextCookieChangeCallback(future_inserted.GetCallback());
  cookie_manager()->SetCanonicalCookie(cookie, kGoogleUrl,
                                       net::CookieOptions::MakeAllInclusive(),
                                       base::DoNothing());

  EXPECT_EQ(future_inserted.Get<1>(), cookie.ExpiryDate());
  EXPECT_EQ(update_expiration_date_call_count_, 3u);
  EXPECT_EQ(cookie_expiration_date_, cookie.ExpiryDate());
}

TEST_F(BoundSessionCookieObserverTest, OpenAiClientTest) {
  http_client_ = std::make_unique<nova::HttpClient>();
  std::unique_ptr<nova::HttpRequest> request =
      std::make_unique<nova::HttpRequest>(GURL("https://example.com"));
  request->SetMethod(nova::HttpRequest::Method::kGetMethod);
  base::RunLoop run_loop;
  std::unique_ptr<nova::HttpResponse> http_response;
  http_client_->Request(std::move(shared_url_loader_factory_),
    std::move(request),
                    base::BindOnce(base::BindLambdaForTesting(
                        [&http_response,
                         &run_loop](std::unique_ptr<nova::HttpResponse> response) {
                          http_response = std::move(response);
                          run_loop.Quit();
                        })));
  run_loop.Run();
  LOG(ERROR) << http_response->status_code << ", " << http_response->body;
}
}  // namespace
