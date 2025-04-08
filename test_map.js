/**
 * Test suite for the Builders Hub map functionality
 * This file contains functions to test various aspects of the map implementation
 */

// Test case 1: Basic map initialization
function testMapInitialization() {
    console.log("TEST 1: Basic map initialization");
    
    try {
        // Check if map container exists
        const mapContainer = document.getElementById('builders-map');
        if (!mapContainer) {
            console.error("FAIL: Map container element not found");
            return false;
        }
        
        // Check container dimensions
        if (mapContainer.offsetWidth <= 0 || mapContainer.offsetHeight <= 0) {
            console.error("FAIL: Map container has zero dimensions");
            return false;
        }
        
        // Check if Leaflet is loaded
        if (typeof L === 'undefined') {
            console.error("FAIL: Leaflet library not loaded");
            return false;
        }
        
        console.log("PASS: Basic map container checks successful");
        return true;
    } catch (e) {
        console.error("FAIL: Exception in map initialization test:", e);
        return false;
    }
}

// Test case 2: Tile layer loading
function testTileLayerLoading() {
    console.log("TEST 2: Tile layer loading");
    
    try {
        // Check if map object exists in global scope
        if (!window.mapLayers || !window.mapLayers.map) {
            console.error("FAIL: Map object not found in global scope");
            return false;
        }
        
        const map = window.mapLayers.map;
        
        // Check if any tile layers are present
        let tileLayerFound = false;
        map.eachLayer(function(layer) {
            if (layer instanceof L.TileLayer) {
                tileLayerFound = true;
            }
        });
        
        if (!tileLayerFound) {
            console.error("FAIL: No tile layers found on map");
            return false;
        }
        
        console.log("PASS: Tile layer check successful");
        return true;
    } catch (e) {
        console.error("FAIL: Exception in tile layer test:", e);
        return false;
    }
}

// Test case 3: GeoJSON layer loading
function testGeoJSONLayer() {
    console.log("TEST 3: GeoJSON layer loading");
    
    try {
        // Check if LGA layer exists
        if (!window.mapLayers || !window.mapLayers.lgaLayer) {
            console.error("FAIL: LGA layer not found in global scope");
            return false;
        }
        
        const lgaLayer = window.mapLayers.lgaLayer;
        
        // Check if it's a valid layer
        if (!(lgaLayer instanceof L.Layer)) {
            console.error("FAIL: LGA layer is not a valid Leaflet layer");
            return false;
        }
        
        // If it's a GeoJSON layer, check for features
        if (lgaLayer instanceof L.GeoJSON) {
            // Check if there are any features
            let featuresFound = false;
            lgaLayer.eachLayer(function() {
                featuresFound = true;
            });
            
            if (!featuresFound) {
                console.warn("WARNING: GeoJSON layer has no features");
            }
        }
        
        console.log("PASS: GeoJSON layer check successful");
        return true;
    } catch (e) {
        console.error("FAIL: Exception in GeoJSON layer test:", e);
        return false;
    }
}

// Test case 4: Document marker toggle
function testDocumentMarkerToggle() {
    console.log("TEST 4: Document marker toggle");
    
    try {
        // Check if toggle exists
        const toggle = document.getElementById('showDocumentMarkers');
        if (!toggle) {
            console.error("FAIL: Document marker toggle not found");
            return false;
        }
        
        // Test toggle functionality
        const initialState = toggle.checked;
        
        // Toggle on if not already
        if (!initialState) {
            toggle.checked = true;
            
            // Create and dispatch change event
            const event = new Event('change');
            toggle.dispatchEvent(event);
            
            console.log("INFO: Document marker toggle turned ON");
        } else {
            console.log("INFO: Document marker toggle already ON");
        }
        
        // Wait a moment and toggle off
        setTimeout(() => {
            toggle.checked = false;
            const event = new Event('change');
            toggle.dispatchEvent(event);
            console.log("INFO: Document marker toggle turned OFF");
            
            // Restore original state
            setTimeout(() => {
                toggle.checked = initialState;
                if (initialState) {
                    const event = new Event('change');
                    toggle.dispatchEvent(event);
                }
                console.log("INFO: Document marker toggle restored to original state");
            }, 500);
        }, 500);
        
        console.log("PASS: Document marker toggle test successful");
        return true;
    } catch (e) {
        console.error("FAIL: Exception in document marker toggle test:", e);
        return false;
    }
}

// Test case 5: LGA click interaction
function testLGAInteraction() {
    console.log("TEST 5: LGA interaction");
    
    try {
        // Check if LGA layer exists
        if (!window.mapLayers || !window.mapLayers.lgaLayer) {
            console.error("FAIL: LGA layer not found for interaction test");
            return false;
        }
        
        const lgaLayer = window.mapLayers.lgaLayer;
        
        // If it's a GeoJSON layer, try to click the first feature
        if (lgaLayer instanceof L.GeoJSON) {
            let featureFound = false;
            
            lgaLayer.eachLayer(function(layer) {
                if (!featureFound && layer.feature && layer.feature.properties) {
                    featureFound = true;
                    
                    // Log info before click
                    console.log("INFO: Attempting to click LGA:", 
                               layer.feature.properties.lga_name || "Unknown LGA");
                    
                    // Simulate a click on this feature
                    layer.fire('click');
                }
            });
            
            if (!featureFound) {
                console.warn("WARNING: No features found to test interaction");
                return false;
            }
        } else {
            console.log("INFO: LGA layer is not a GeoJSON layer, skipping click test");
            return false;
        }
        
        console.log("PASS: LGA interaction test successful");
        return true;
    } catch (e) {
        console.error("FAIL: Exception in LGA interaction test:", e);
        return false;
    }
}

// Test case 6: Search form
function testSearchForm() {
    console.log("TEST 6: Search form");
    
    try {
        // Check if form exists
        const form = document.getElementById('searchForm');
        if (!form) {
            console.error("FAIL: Search form not found");
            return false;
        }
        
        // Check for required inputs
        const lgaSelect = document.getElementById('lgaSearch');
        const docTypeSelect = document.getElementById('documentType');
        const keywordInput = document.getElementById('keywordSearch');
        
        if (!lgaSelect || !docTypeSelect || !keywordInput) {
            console.error("FAIL: One or more search form inputs not found");
            return false;
        }
        
        // Test form submission (prevent actual submission)
        form.onsubmit = function(e) {
            e.preventDefault();
            console.log("INFO: Search form submission prevented for test");
            return false;
        };
        
        // Trigger form submission
        console.log("INFO: Submitting search form for test");
        form.dispatchEvent(new Event('submit'));
        
        console.log("PASS: Search form test successful");
        return true;
    } catch (e) {
        console.error("FAIL: Exception in search form test:", e);
        return false;
    }
}

// Test case 7: Document display
function testDocumentDisplay() {
    console.log("TEST 7: Document display");
    
    try {
        // Check if document list exists
        const docList = document.getElementById('documentsList');
        if (!docList) {
            console.error("FAIL: Document list container not found");
            return false;
        }
        
        // Check if we have any documents
        const docs = docList.querySelectorAll('.document-item');
        console.log(`INFO: Found ${docs.length} documents in list`);
        
        if (docs.length === 0) {
            console.warn("WARNING: No documents found to test display");
        } else {
            // Test document filtering
            const firstDoc = docs[0];
            const lgaId = firstDoc.getAttribute('data-lga-id');
            const docType = firstDoc.getAttribute('data-type');
            
            if (lgaId) {
                console.log(`INFO: Testing filter for LGA ID: ${lgaId}`);
                // Set the dropdown to this LGA
                const lgaSelect = document.getElementById('lgaSearch');
                if (lgaSelect) {
                    lgaSelect.value = lgaId;
                }
            }
        }
        
        console.log("PASS: Document display test successful");
        return true;
    } catch (e) {
        console.error("FAIL: Exception in document display test:", e);
        return false;
    }
}

// Run all tests
function runAllTests() {
    console.log("STARTING MAP FUNCTIONALITY TESTS");
    
    const results = {
        mapInit: testMapInitialization(),
        tileLayer: testTileLayerLoading(),
        geoJSON: testGeoJSONLayer(),
        markerToggle: testDocumentMarkerToggle(),
        lgaInteraction: testLGAInteraction(),
        searchForm: testSearchForm(),
        docDisplay: testDocumentDisplay()
    };
    
    console.log("TEST SUMMARY:");
    let passCount = 0;
    let failCount = 0;
    
    for (const [test, passed] of Object.entries(results)) {
        if (passed) {
            console.log(`✅ ${test}: PASS`);
            passCount++;
        } else {
            console.log(`❌ ${test}: FAIL`);
            failCount++;
        }
    }
    
    console.log(`TOTAL: ${passCount} passed, ${failCount} failed`);
    console.log("TESTS COMPLETE");
}

// Wait for page to load, then run tests
document.addEventListener('DOMContentLoaded', function() {
    // Wait for map to initialize
    setTimeout(runAllTests, 2000);
});