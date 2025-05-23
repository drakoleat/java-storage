package com.google.cloud.storage;

import static com.google.common.base.Charsets.UTF_8;
import static org.easymock.EasyMock.createMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import com.google.auth.ServiceAccountSigner;
import com.google.cloud.Clock;
import com.google.cloud.storage.Storage.PostPolicyV4Option;
import com.google.cloud.storage.Storage.SignUrlOption;
import com.google.common.collect.ImmutableMap;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.junit.Before;
import org.junit.Test;

public class SignatureAlgorithmTest {

  private static final String BUCKET_NAME = "test-bucket";
  private static final String BLOB_NAME = "test-blob";
  private static final String ACCOUNT_EMAIL = "test@gserviceaccount.com";
  private static final long TIMESTAMP = 1440981390000L;
  private static final HttpStorageOptions OPTIONS = HttpStorageOptions.newBuilder().build();
  private static final ServiceAccountSigner MY_SIGNER = createMock(ServiceAccountSigner.class);
  private static final Clock MY_CLOCK = createMock(Clock.class);
  private static final String SIGNATURE = "signature";
  private static final String SIGNATURE_V4 =
      "50604f4f47342d5253412d5348413235360a3230313530383330543132333633305a0a32303135303833302f6175746f2f73746f726167652f676f6f67345f726571756573740a33393432323563653937653234656466626265316561646237323032343139383234663130306366656237386564303931323931383030346632316633346537";
  private static final String POLICY = "policy";
  private static final Map<String, String> SIGNED_EXT_HEADERS =
      ImmutableMap.of("x-goog-acl", "public-read");
  private static final String HMAC_SIGNATURE_V4 =
      "474f4f47342d484d41432d5348413235360a3230313530383330543132333633305a0a32303135303833302f6175746f2f73746f726167652f676f6f67345f726571756573740a";
  private static final BlobInfo INFO = BlobInfo.newBuilder(BUCKET_NAME, BLOB_NAME).build();
  private static final BlobInfo INFO_WITH_GENERATION =
      BlobInfo.newBuilder(BUCKET_NAME, BLOB_NAME, 1L).build();
  private static final String SIGNATURE_V4_CANONICAL_REQUEST_HASH =
      "394225ce97e24edfbbe1eadb7202419824f100cfeb78ed0912918004f21f34e7";
  private static final String SIGNATURE_V4_BEGINNING = "GOOG4-RSA-SHA256\n" + "20150830T123630Z\n" + "20150830/auto/storage/goog4_request\n";

  @Before
  public void setUp() {
    expect(OPTIONS.getClock()).andReturn(MY_CLOCK).anyTimes();
    expect(MY_CLOCK.millisTime()).andReturn(TIMESTAMP).anyTimes();
  }

  @Test
  public void testSignUrlHmac() throws MalformedURLException {
    expect(MY_SIGNER.getAccount()).andReturn(ACCOUNT_EMAIL).times(2);
    expect(MY_SIGNER.sign((HMAC_SIGNATURE_V4 + SIGNATURE_V4_CANONICAL_REQUEST_HASH).getBytes(UTF_8)))
        .andReturn(SIGNATURE.getBytes(UTF_8))
        .times(2);
    replay(OPTIONS, MY_SIGNER, MY_CLOCK);
    Storage storage = OPTIONS.getService();
    URL signedUrl =
        storage.signUrl(
            INFO_WITH_GENERATION,
            1,
            TimeUnit.HOURS,
            SignUrlOption.withV4Signature(),
            SignUrlOption.signWith(MY_SIGNER),
            SignUrlOption.withSignatureAlgorithm("GOOG4-HMAC-SHA256"));
    assertTrue(signedUrl.getQuery().contains("X-Goog-Algorithm=GOOG4-HMAC-SHA256"));
    assertTrue(signedUrl.getQuery().contains("X-Goog-Signature=" + SIGNATURE));
    signedUrl =
        storage.signUrl(
            INFO_WITH_GENERATION,
            1,
            TimeUnit.HOURS,
            SignUrlOption.withV4Signature(),
            SignUrlOption.withPathStyle(),
            SignUrlOption.signWith(MY_SIGNER),
            SignUrlOption.withSignatureAlgorithm("GOOG4-HMAC-SHA256"));
    assertTrue(signedUrl.getQuery().contains("X-Goog-Algorithm=GOOG4-HMAC-SHA256"));
    assertTrue(signedUrl.getQuery().contains("X-Goog-Signature=" + SIGNATURE));
  }

  @Test
  public void testSignUrlDefaultAlgorithm() throws MalformedURLException {
    expect(MY_SIGNER.getAccount()).andReturn(ACCOUNT_EMAIL).times(2);
    expect(MY_SIGNER.sign((SIGNATURE_V4_BEGINNING + SIGNATURE_V4_CANONICAL_REQUEST_HASH).getBytes(UTF_8)))
        .andReturn(SIGNATURE.getBytes(UTF_8))
        .times(2);
    replay(OPTIONS, MY_SIGNER, MY_CLOCK);
    Storage storage = OPTIONS.getService();
    URL signedUrl =
        storage.signUrl(
            INFO_WITH_GENERATION,
            1,
            TimeUnit.HOURS,
            SignUrlOption.withV4Signature(),
            SignUrlOption.signWith(MY_SIGNER));
    assertTrue(signedUrl.getQuery().contains("X-Goog-Algorithm=GOOG4-RSA-SHA256"));
    assertTrue(signedUrl.getQuery().contains("X-Goog-Signature=" + SIGNATURE));
    signedUrl =
        storage.signUrl(
            INFO_WITH_GENERATION,
            1,
            TimeUnit.HOURS,
            SignUrlOption.withV4Signature(),
            SignUrlOption.withPathStyle(),
            SignUrlOption.signWith(MY_SIGNER));
    assertTrue(signedUrl.getQuery().contains("X-Goog-Algorithm=GOOG4-RSA-SHA256"));
    assertTrue(signedUrl.getQuery().contains("X-Goog-Signature=" + SIGNATURE));
  }

  @Test
  public void testGenerateSignedPostPolicyV4Hmac() {
    expect(MY_SIGNER.getAccount()).andReturn(ACCOUNT_EMAIL);
    expect(MY_SIGNER.sign(POLICY.getBytes(UTF_8))).andReturn(SIGNATURE.getBytes(UTF_8));
    replay(OPTIONS, MY_SIGNER, MY_CLOCK);
    Storage storage = OPTIONS.getService();
    PostPolicyV4 policy =
        storage.generateSignedPostPolicyV4(
            INFO,
            1,
            TimeUnit.HOURS,
            PostPolicyV4Option.signWith(MY_SIGNER),
            PostPolicyV4Option.signatureAlgorithm("GOOG4-HMAC-SHA256"));
    assertTrue(policy.getFields().containsKey("x-goog-algorithm"));
    assertEquals("GOOG4-HMAC-SHA256", policy.getFields().get("x-goog-algorithm"));
  }

  @Test
  public void testGenerateSignedPostPolicyV4DefaultAlgorithm() {
    expect(MY_SIGNER.getAccount()).andReturn(ACCOUNT_EMAIL);
    expect(MY_SIGNER.sign(POLICY.getBytes(UTF_8))).andReturn(SIGNATURE.getBytes(UTF_8));
    replay(OPTIONS, MY_SIGNER, MY_CLOCK);
    Storage storage = OPTIONS.getService();
    PostPolicyV4 policy =
        storage.generateSignedPostPolicyV4(
            INFO, 1, TimeUnit.HOURS, PostPolicyV4Option.signWith(MY_SIGNER));
    assertTrue(policy.getFields().containsKey("x-goog-algorithm"));
    assertEquals("GOOG4-RSA-SHA256", policy.getFields().get("x-goog-algorithm"));
  }
}
