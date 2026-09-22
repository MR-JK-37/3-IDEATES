/**
 * Phishing Detection Engine
 * ML-powered URL analysis for phishing detection
 * Uses TensorFlow Lite for on-device inference
 */

import {IEngine, EngineStatus} from './interfaces/IEngine';
import {Threat, ThreatType, ThreatLevel, PhishingAssessment} from '../types';
import {store} from '../store';
import {addThreat} from '../store/slices/threatsSlice';
import {v4 as uuidv4} from 'uuid';
import {isValidUrl, extractDomain, isSuspiciousDomain} from '../utils/helpers';

class PhishingDetectorEngine implements IEngine {
  private running: boolean = false;
  private lastScanTime: number = 0;
  private threatsDetected: number = 0;
  private errors: string[] = [];
  private mlModel: any = null; // TensorFlow Lite model

  async initialize(): Promise<void> {
    console.log('PhishingDetectorEngine: Initializing...');
    // Load TensorFlow Lite model
    // This will be implemented with @tensorflow/tfjs-react-native
    try {
      // TODO: Load phishing detection model
      // const modelUrl = require('../models/phishing_detector.tflite');
      // this.mlModel = await tf.loadLayersModel(modelUrl);
      console.log('PhishingDetectorEngine: Model loaded (placeholder)');
    } catch (error) {
      console.error('PhishingDetectorEngine: Failed to load model:', error);
      this.errors.push('Failed to load ML model');
    }
  }

  async start(): Promise<void> {
    if (this.running) {
      console.warn('PhishingDetectorEngine: Already running');
      return;
    }

    this.running = true;
    console.log('PhishingDetectorEngine: Started');
  }

  async stop(): Promise<void> {
    this.running = false;
    console.log('PhishingDetectorEngine: Stopped');
  }

  isRunning(): boolean {
    return this.running;
  }

  getStatus(): EngineStatus {
    return {
      running: this.running,
      lastScanTime: this.lastScanTime,
      threatsDetected: this.threatsDetected,
      errors: [...this.errors],
    };
  }

  /**
   * Analyze URL for phishing
   */
  async analyzeURL(url: string): Promise<PhishingAssessment> {
    if (!this.running) {
      throw new Error('PhishingDetectorEngine: Not running');
    }

    if (!isValidUrl(url)) {
      return {
        isPhishing: false,
        confidence: 0,
        reasons: ['Invalid URL format'],
        url: url,
        domain: '',
      };
    }

    const domain = extractDomain(url) || '';
    const reasons: string[] = [];

    // Rule-based checks
    if (isSuspiciousDomain(domain)) {
      reasons.push('Suspicious domain pattern');
    }

    // Check for homograph attacks (lookalike domains)
    if (this.detectHomograph(domain)) {
      reasons.push('Homograph attack detected');
    }

    // Check URL length (phishing URLs are often long)
    if (url.length > 100) {
      reasons.push('Unusually long URL');
    }

    // Check for IP address in URL (suspicious)
    if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(url)) {
      reasons.push('IP address in URL');
    }

    // ML-based detection (if model is loaded)
    let mlConfidence = 0;
    if (this.mlModel) {
      try {
        const features = this.extractFeatures(url);
        // TODO: Run ML model inference
        // const prediction = await this.mlModel.predict(features);
        // mlConfidence = prediction[0];
        mlConfidence = 0.5; // Placeholder
      } catch (error) {
        console.error('PhishingDetectorEngine: ML inference error:', error);
      }
    }

    // Calculate overall confidence
    const ruleBasedConfidence = reasons.length > 0 ? 0.7 : 0.3;
    const confidence = Math.max(ruleBasedConfidence, mlConfidence);

    const isPhishing = confidence > 0.6 || reasons.length >= 2;

    if (isPhishing) {
      await this.createThreatForPhishing(url, domain, reasons, confidence);
    }

    this.lastScanTime = Date.now();

    return {
      isPhishing,
      confidence,
      reasons,
      url,
      domain,
      certificateValid: true, // Would be checked in real implementation
    };
  }

  /**
   * Extract features from URL for ML model
   */
  private extractFeatures(url: string): number[] {
    // Feature extraction for ML model
    // Features: URL length, domain length, number of subdomains, etc.
    const domain = extractDomain(url) || '';
    return [
      url.length / 200, // Normalized URL length
      domain.length / 50, // Normalized domain length
      (url.match(/\./g) || []).length / 10, // Number of dots
      url.includes('https') ? 1 : 0, // HTTPS
      url.includes('http://') ? 1 : 0, // HTTP (suspicious)
      (url.match(/-/g) || []).length / 10, // Number of hyphens
    ];
  }

  /**
   * Detect homograph attacks (lookalike domains)
   */
  private detectHomograph(domain: string): boolean {
    // Check for character substitution (e.g., rn -> m, 0 -> O)
    const homographPatterns = [
      /rn/g, // rn looks like m
      /[0-9]/g, // Numbers in domain
    ];

    return homographPatterns.some(pattern => pattern.test(domain));
  }

  /**
   * Create threat for phishing URL
   */
  private async createThreatForPhishing(
    url: string,
    domain: string,
    reasons: string[],
    confidence: number,
  ): Promise<void> {
    const threat: Threat = {
      id: uuidv4(),
      type: ThreatType.PHISHING,
      level: confidence > 0.8 ? ThreatLevel.CRITICAL : ThreatLevel.HIGH,
      timestamp: Date.now(),
      detectedBy: 'PhishingDetectorEngine',
      title: 'Phishing Website Detected',
      description: `Phishing website detected: ${domain}`,
      technicalDetails: `URL: ${url}, Domain: ${domain}, Confidence: ${(confidence * 100).toFixed(1)}%, Reasons: ${reasons.join(', ')}`,
      userFriendlyExplanation:
        'A fake website was detected trying to steal your login credentials. Never enter your password on suspicious websites. Always check the URL before entering sensitive information.',
      blocked: true,
      actions: [
        {
          type: 'BLOCKED',
          timestamp: Date.now(),
          description: 'Phishing website blocked',
        },
        {
          type: 'ALERTED',
          timestamp: Date.now(),
          description: 'User alerted about phishing attempt',
        },
      ],
      metadata: {
        url: url,
        domain: domain,
        confidence: confidence,
        reasons: reasons,
      },
    };

    store.dispatch(addThreat(threat));
    this.threatsDetected++;
  }
}

export default new PhishingDetectorEngine();
