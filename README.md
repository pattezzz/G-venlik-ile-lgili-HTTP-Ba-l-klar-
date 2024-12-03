Güvenlik ile İlgili HTTP Başlıkları
X-XSS-Protection
XSS saldırılarına karşı tarayıcı korumasını etkinleştirir.

Örnek: X-XSS-Protection: 1; mode=block
X-Content-Type-Options
Tarayıcının MIME türlerini "tahmin etmesini" engeller.

Örnek: X-Content-Type-Options: nosniff
X-Frame-Options
Sayfanın bir iframe içinde yüklenip yüklenemeyeceğini kontrol eder (Clickjacking saldırılarına karşı).

Örnek: X-Frame-Options: DENY
Strict-Transport-Security (HSTS)
Sadece HTTPS üzerinden bağlantıya izin verir ve HTTP'yi reddeder.

Örnek: Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Security-Policy (CSP)
Kaynakların hangi alanlardan yükleneceğini kontrol eder.

Örnek: Content-Security-Policy: default-src 'self'
Referrer-Policy
Hangi yönlendirme bilgilerini paylaşacağını belirler.

Örnek: Referrer-Policy: no-referrer
Permissions-Policy (Önceki adı: Feature-Policy)
Belirli tarayıcı API’lerini kısıtlar (örneğin, kamera veya mikrofon).

Örnek: Permissions-Policy: geolocation=(), microphone=()
X-Permitted-Cross-Domain-Policies
Flash içeriklerin hangi alanlardan veri alabileceğini belirler.

Örnek: X-Permitted-Cross-Domain-Policies: none
X-Download-Options
Dosya indirme işlemlerinde tarayıcı korumasını artırır.

Örnek: X-Download-Options: noopen
Cache-Control
Önbellekleme davranışını kontrol eder.

Örnek: Cache-Control: no-store, no-cache, must-revalidate
Set-Cookie
Çerezler ile ilgili ek güvenlik bayraklarını ayarlamak için kullanılır.

Örnek: Set-Cookie: key=value; HttpOnly; Secure; SameSite=Strict
Performans ve Diğer Başlıklar
X-Powered-By
Sunucu tarafındaki teknolojiyi belirtir (güvenlik için gizlenmesi önerilir).

Örnek: X-Powered-By: ASP.NET
Server
Sunucunun adını veya türünü belirtir.

Örnek: Server: nginx/1.18.0
X-Cache
Önbellek sonuçlarını gösterir (HIT, MISS).

Örnek: X-Cache: MISS
Access-Control-Allow-Origin (CORS)
Hangi alanların kaynaklara erişebileceğini kontrol eder.

Örnek: Access-Control-Allow-Origin: *
X-RateLimit-Limit
İzin verilen maksimum istek sayısını belirtir (API'ler için).

Örnek: X-RateLimit-Limit: 1000
Retry-After
Hangi süre sonra isteğin yeniden denenebileceğini belirtir (genelde 429 veya 503 hata kodlarında).

Örnek: Retry-After: 120
ETag
İçeriğin sürüm bilgilerini taşır ve önbelleklemede kullanılır.

Örnek: ETag: "abc123"
Last-Modified
Kaynağın en son ne zaman değiştirildiğini belirtir.

Örnek: Last-Modified: Wed, 21 Oct 2023 07:28:00 GMT
Ek Başlıklar
X-Forwarded-For
İstek yapan istemcinin gerçek IP adresini iletir.

Örnek: X-Forwarded-For: 192.168.1.1
X-Forwarded-Proto
İsteğin protokolünü belirtir (HTTP veya HTTPS).

Örnek: X-Forwarded-Proto: https
X-Amz-Cf-Pop
CloudFront sunucu konumunu belirtir.

Örnek: X-Amz-Cf-Pop: AMS54-C1
X-Amz-Request-Id
AWS istek kimliği.

Örnek: X-Amz-Request-Id: abc123

AWS (Amazon Web Services) X-headers, genellikle AWS CloudFront ve diğer hizmetlerle ilgili detayları taşır. İşte en yaygın X-headers ve kısa açıklamaları:

X-Amz-Cf-Pop
CloudFront pop (Point of Presence) yani içerik dağıtım sunucusunun konumunu belirtir.

X-Amz-Cf-Id
CloudFront isteğine özgü bir kimlik; sorun gidermede kullanılır.

X-Amz-Date
İstek zamanı damgasını belirtir (ISO 8601 formatında).

X-Amz-Security-Token
AWS Geçici Kimlik Bilgileri ile ilişkili güvenlik belirteci.

X-Amz-Request-Id
AWS sunucusunun isteği izlemek için kullandığı benzersiz kimlik.

X-Amz-Expires
İmza ile yetkilendirilmiş URL'nin geçerlilik süresini belirtir.

X-Amz-Meta-*
S3 nesnelerine eklenen özel meta veriler.

X-Amz-SignedHeaders
İmza işlemine dahil edilen başlıkları listeler.

X-Amz-Content-Sha256
Gönderilen içeriğin SHA-256 hash değeri.

X-Amz-Algorithm
İmzalama sırasında kullanılan algoritmayı belirtir (ör. AWS4-HMAC-SHA256).

X-Forwarded-For
İstek yapan istemcinin IP adresini gösterir (özellikle bir proxy veya load balancer kullanılıyorsa).

X-Forwarded-Proto
İsteğin protokolünü belirtir (http veya https).

X-Edge-Result-Type
CloudFront'un istek sonucunu nasıl işlediğini belirtir (ör. Miss, Hit).

X-Edge-Request-ID
İstekle ilişkilendirilmiş CloudFront'un iç benzersiz kimliği.

X-Cache
İsteğin önbellekten mi geldiğini (Hit) yoksa kaynak sunucuya mı yönlendirildiğini (Miss) gösterir.AWS (Amazon Web Services) X-headers, genellikle AWS CloudFront ve diğer hizmetlerle ilgili detayları taşır. İşte en yaygın X-headers ve kısa açıklamaları:

X-Amz-Cf-Pop
CloudFront pop (Point of Presence) yani içerik dağıtım sunucusunun konumunu belirtir.

X-Amz-Cf-Id
CloudFront isteğine özgü bir kimlik; sorun gidermede kullanılır.

X-Amz-Date
İstek zamanı damgasını belirtir (ISO 8601 formatında).

X-Amz-Security-Token
AWS Geçici Kimlik Bilgileri ile ilişkili güvenlik belirteci.

X-Amz-Request-Id
AWS sunucusunun isteği izlemek için kullandığı benzersiz kimlik.

X-Amz-Expires
İmza ile yetkilendirilmiş URL'nin geçerlilik süresini belirtir.

X-Amz-Meta-*
S3 nesnelerine eklenen özel meta veriler.

X-Amz-SignedHeaders
İmza işlemine dahil edilen başlıkları listeler.

X-Amz-Content-Sha256
Gönderilen içeriğin SHA-256 hash değeri.

X-Amz-Algorithm
İmzalama sırasında kullanılan algoritmayı belirtir (ör. AWS4-HMAC-SHA256).

X-Forwarded-For
İstek yapan istemcinin IP adresini gösterir (özellikle bir proxy veya load balancer kullanılıyorsa).

X-Forwarded-Proto
İsteğin protokolünü belirtir (http veya https).

X-Edge-Result-Type
CloudFront'un istek sonucunu nasıl işlediğini belirtir (ör. Miss, Hit).

X-Edge-Request-ID
İstekle ilişkilendirilmiş CloudFront'un iç benzersiz kimliği.

X-Cache
İsteğin önbellekten mi geldiğini (Hit) yoksa kaynak sunucuya mı yönlendirildiğini (Miss) gösterir.
