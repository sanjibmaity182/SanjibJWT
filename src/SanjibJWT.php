<?php
/**
 * SanjibJWT - A secure JWT implementation with IP validation and custom headers
 * 
 * Features:
 * - No database required
 * - IP-based access control
 * - Custom header validation
 * - Server map rotation for encoding
 * - Secure token generation and validation
 */

class SanjibJWT {
    // Server maps for character substitution
    private $serverMaps = [];
    
    // Configuration
    private $config = [
        'secret' => 'your-very-secure-secret-key-change-this',
        'algorithm' => 'HS256',
        'leeway' => 60, // 1 minute leeway for clock skew
        'access_token_expire' => 3600, // 1 hour
        'allowed_ips' => ['127.0.0.1', '::1'], // Allowed IPs
        'require_https' => true
    ];
    
    private $errors = [];
    
    public function __construct($config = []) {
        // Merge custom config with defaults
        $this->config = array_merge($this->config, $config);
        
        // Initialize server maps
        $this->initServerMaps();
    }
    
    /**
     * Initialize server maps for character substitution
     */
    private function initServerMaps() {
        // Define multiple server maps for rotation
        $this->serverMaps = [
            // Map 0
            [
                'A' => 'M', 'B' => 'Z', 'C' => 'T', 'D' => 'X', 'E' => '5', 'F' => 'I', 'G' => '2', 
                'H' => 'a', 'I' => '1', 'J' => 'q', 'K' => 'A', 'L' => 'Q', 'M' => '=', 'N' => 's', 
                'O' => 'p', 'P' => '0', 'Q' => 'h', 'R' => 'E', 'S' => 'g', 'T' => 't', 'U' => 'C', 
                'V' => 'P', 'W' => 'j', 'X' => 'u', 'Y' => 'O', 'Z' => 'o', 'a' => 'e', 'b' => 'R', 
                'c' => 'c', 'd' => 'r', 'e' => '8', 'f' => 'l', 'g' => 'J', 'h' => 'N', 'i' => '3', 
                'j' => 'D', 'k' => 'n', 'l' => 'Y', 'm' => 'm', 'n' => 'W', 'o' => 'v', 'p' => 'k', 
                'q' => '7', 'r' => 'K', 's' => 'w', 't' => 'V', 'u' => 'U', 'v' => 'y', 'w' => '9', 
                'x' => 'H', 'y' => 'L', 'z' => '6', '0' => 'i', '1' => 'd', '2' => '/', '3' => 'S', 
                '4' => 'F', '5' => '4', '6' => 'f', '7' => 'B', '8' => 'b', '9' => '+', '+' => 'x', 
                '/' => 'z', '=' => 'G'
            ],
            // Map 1 - Add more maps as needed
            [
                'A' => '6', 'B' => 'o', 'C' => 'q', 'D' => '1', 'E' => '3', 'F' => 'e', 'G' => 'D', 
                'H' => 'Z', 'I' => 'G', 'J' => 'J', 'K' => 'S', 'L' => 'g', 'M' => 'O', 'N' => 'p', 
                'O' => 'C', 'P' => 'd', 'Q' => '5', 'R' => 'l', 'S' => 'Y', 'T' => 'k', 'U' => 'y', 
                'V' => 'h', 'W' => '0', 'X' => '7', 'Y' => 'L', 'Z' => 'n', 'a' => 't', 'b' => '+', 
                'c' => 'z', 'd' => 'E', 'e' => 'B', 'f' => 'H', 'g' => 'A', 'h' => '=', 'i' => 'U', 
                'j' => 'R', 'k' => 'V', 'l' => 'a', 'm' => 'N', 'n' => 'r', 'o' => 'Q', 'p' => 'M', 
                'q' => 'I', 'r' => '/', 's' => 'w', 't' => 'b', 'u' => 'v', 'v' => 'c', 'w' => 's', 
                'x' => 'f', 'y' => 'X', 'z' => 'j', '0' => 'i', '1' => '4', '2' => 'W', '3' => '2', 
                '4' => '9', '5' => 'F', '6' => 'm', '7' => 'P', '8' => 'u', '9' => 'x', '+' => 'K', 
                '/' => 'T', '=' => '8'
            ]
            // Add more maps as needed
        ];
    }
    
    /**
     * Get current server map based on time
     */
    private function getServerMap() {
        $time = time();
        $mapIndex = $time % count($this->serverMaps);
        return $this->serverMaps[$mapIndex];
    }
    
    /**
     * Encode string using server map
     */
    private function encodeWithMap($str) {
        $map = $this->getServerMap();
        $result = '';
        $length = strlen($str);
        
        for ($i = 0; $i < $length; $i++) {
            $char = $str[$i];
            $result .= $map[$char] ?? $char;
        }
        
        return $result;
    }
    
    /**
     * Decode string using server map
     */
    private function decodeWithMap($str) {
        $map = $this->getServerMap();
        $reverseMap = array_flip($map);
        $result = '';
        $length = strlen($str);
        
        for ($i = 0; $i < $length; $i++) {
            $char = $str[$i];
            $result .= $reverseMap[$char] ?? $char;
        }
        
        return $result;
    }
    
    /**
     * Create a new JWT token with custom headers and IP validation
     */
    public function createToken($payload, $customHeaders = []) {
        // Reset errors
        $this->errors = [];
        
        // Validate payload
        if (empty($payload['user_id'])) {
            $this->errors[] = 'User ID is required';
            return false;
        }
        
        // Check IP restriction
        $ip = $this->getClientIP();
        if (!empty($this->config['allowed_ips']) && !in_array($ip, $this->config['allowed_ips'])) {
            $this->errors[] = 'IP address not allowed';
            return false;
        }
        
        // Create token header
        $header = array_merge([
            'typ' => 'JWT',
            'alg' => $this->config['algorithm'],
            'map' => time() % count($this->serverMaps), // Store which map was used
            'ip' => $this->hashIP($ip) // Store hashed IP
        ], $customHeaders);
        
        // Set token expiration
        $time = time();
        $payload['iat'] = $time;
        $payload['exp'] = $time + $this->config['access_token_expire'];
        $payload['jti'] = bin2hex(random_bytes(16)); // Unique token ID
        
        // Encode header and payload
        $encodedHeader = $this->base64UrlEncode(json_encode($header));
        $encodedPayload = $this->base64UrlEncode(json_encode($payload));
        
        // Create signature
        $signature = $this->sign("$encodedHeader.$encodedPayload");
        
        // Encode the final token with server map
        $token = "$encodedHeader.$encodedPayload.$signature";
        $encodedToken = $this->encodeWithMap($token);
        
        return [
            'access_token' => $encodedToken,
            'expires_in' => $this->config['access_token_expire'],
            'token_type' => 'Bearer'
        ];
    }
    
    /**
     * Validate a JWT token with IP and header validation
     */
    public function validateToken($encodedToken, $validateIP = true, $validateHeaders = []) {
        // Reset errors
        $this->errors = [];
        
        try {
            // Decode the token using server map
            $token = $this->decodeWithMap($encodedToken);
            
            // Split token
            $parts = explode('.', $token);
            if (count($parts) !== 3) {
                throw new Exception('Invalid token format');
            }
            
            list($encodedHeader, $encodedPayload, $signature) = $parts;
            
            // Decode header and payload
            $header = json_decode($this->base64UrlDecode($encodedHeader), true);
            $payload = json_decode($this->base64UrlDecode($encodedPayload), true);
            
            if (empty($header) || empty($payload)) {
                throw new Exception('Invalid token data');
            }
            
            // Verify signature
            if (!$this->verify("$encodedHeader.$encodedPayload", $signature)) {
                throw new Exception('Invalid token signature');
            }
            
            // Check expiration
            if (isset($payload['exp']) && time() > $payload['exp'] + $this->config['leeway']) {
                throw new Exception('Token has expired');
            }
            
            // Check IP if required
            if ($validateIP && isset($header['ip'])) {
                $clientIP = $this->getClientIP();
                $hashedIP = $this->hashIP($clientIP);
                
                if ($header['ip'] !== $hashedIP) {
                    throw new Exception('Token IP mismatch');
                }
            }
            
            // Validate custom headers
            foreach ($validateHeaders as $key => $expectedValue) {
                if (!isset($header[$key]) || $header[$key] !== $expectedValue) {
                    throw new Exception("Invalid token header: $key");
                }
            }
            
            return $payload;
            
        } catch (Exception $e) {
            $this->errors[] = $e->getMessage();
            return false;
        }
    }
    
    /**
     * Hash IP address for secure storage in token
     */
    private function hashIP($ip) {
        return hash_hmac('sha256', $ip, $this->config['secret']);
    }
    
    /**
     * Get client IP address
     */
    private function getClientIP() {
        if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
            return $_SERVER['HTTP_CLIENT_IP'];
        } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            return $_SERVER['HTTP_X_FORWARDED_FOR'];
        } else {
            return $_SERVER['REMOTE_ADDR'];
        }
    }
    
    /**
     * Sign the data
     */
    private function sign($data) {
        return $this->base64UrlEncode(
            hash_hmac('sha256', $data, $this->config['secret'], true)
        );
    }
    
    /**
     * Verify the signature
     */
    private function verify($data, $signature) {
        $hash = hash_hmac('sha256', $data, $this->config['secret'], true);
        $sig = $this->base64UrlDecode($signature);
        return hash_equals($sig, $hash);
    }
    
    /**
     * Base64 URL encode
     */
    private function base64UrlEncode($data) {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }
    
    /**
     * Base64 URL decode
     */
    private function base64UrlDecode($data) {
        return base64_decode(str_pad(
            strtr($data, '-_', '+/'),
            strlen($data) % 4,
            '=',
            STR_PAD_RIGHT
        ));
    }
    
    /**
     * Get errors
     */
    public function getErrors() {
        return $this->errors;
    }
    
    /**
     * Get last error
     */
    public function getLastError() {
        return end($this->errors) ?: null;
    }
}
