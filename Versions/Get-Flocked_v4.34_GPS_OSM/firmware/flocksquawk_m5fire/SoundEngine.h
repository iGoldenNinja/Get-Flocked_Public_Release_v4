#ifndef SOUND_ENGINE_H
#define SOUND_ENGINE_H

#include <Arduino.h>
#include <FS.h>
#include <SD.h>
#include <M5Unified.h>
#include "EventBus.h"

class SoundEngine {
public:
    static const uint8_t SD_SCK = 18;
    static const uint8_t SD_MISO = 19;
    static const uint8_t SD_MOSI = 23;
    static const uint8_t SD_CS = 4;
    static constexpr float DEFAULT_VOLUME = 0.30f;
    static constexpr float MAX_SPEAKER_GAIN = 0.65f;
    static constexpr bool USE_WAV_FILES = false;
    static constexpr const char* TONE_PROFILE_PATH = "/sound_tones.csv";

    void initialize();
    void setVolume(float level);
    float getVolumeLevel() const;
    void playSound(const char* filename);
    void playSoundAsync(const char* filename);
    void playSoundAsyncAtConfidence(const char* filename, uint8_t certainty);
    void playConfidenceBeep(uint8_t certainty, AlertLevel level);
    void update();
    void handleAudioRequest(const AudioEvent& event);
    
private:
    float volumeLevel;
    uint8_t* asyncBuffer = nullptr;
    size_t asyncLength = 0;
    bool asyncActive = false;
    bool tempVolumeActive = false;
    uint32_t tempVolumeRestoreMs = 0;

    struct WavInfo {
        bool pcm;
        uint16_t channels;
        uint16_t bitsPerSample;
        uint32_t sampleRate;
    };
    
    bool loadWavFromSd(const char* filename, uint8_t** outData, size_t* outLength);
    bool inspectWavBuffer(const uint8_t* data, size_t length, WavInfo* info) const;
    bool isSupportedWav(const WavInfo& info) const;
    const char* soundNameFromFilename(const char* filename) const;
    bool playCustomToneSequence(const char* soundName);
    bool playDefaultToneSequence(const char* soundName, bool asyncMode);
    bool playToneFallback(const char* filename, bool asyncMode);
    void applySpeakerVolume(float level);
    void applyTemporaryConfidenceVolume(uint8_t certainty, uint16_t holdMs);
    void restoreTemporaryVolumeIfNeeded();
    float confidenceVolumeScale(uint8_t certainty) const;
};

#endif
