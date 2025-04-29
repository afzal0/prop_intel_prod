/**
 * Shared LGA mapping utilities for PropIntel
 * This ensures all maps use the same LGA boundary data consistently
 */

// Initialize the LGA layer with proper styling and behavior
function initLgaLayer(map, options = {}) {
    // Default options
    const defaultOptions = {
        showPopup: true,               // Whether to show popups on LGA click
        highlightOnHover: true,        // Whether to highlight LGAs on hover
        clickHandler: null,            // Custom click handler function
        styleCallback: null,           // Custom style function
        filterCallback: null,          // Custom filter function
        getPropertiesCallback: null    // Function to get properties data for statistics
    };
    
    // Merge default options with provided options
    const settings = {...defaultOptions, ...options};
    
    // Remove existing LGA layer if present
    if (window.currentLgaLayer && map.hasLayer(window.currentLgaLayer)) {
        map.removeLayer(window.currentLgaLayer);
    }
    
    // Default LGA style
    const defaultStyle = {
        color: '#3388ff',
        weight: 1,
        opacity: 0.6,
        fillOpacity: 0.1,
        fillColor: '#3388ff'
    };
    
    // Create the LGA layer
    console.log('Loading LGA boundaries from server...');
    
    // Use builders-hub endpoint to get consistent LGA data with document counts
    fetch('/builders-hub?lga_geojson=true')
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(lgaData => {
            console.log(`Loaded ${lgaData.features ? lgaData.features.length : 0} LGA features`);
            
            // Create LGA layer with styling
            const lgaLayer = L.geoJSON(lgaData, {
                style: function(feature) {
                    // Use custom style callback if provided
                    if (settings.styleCallback && typeof settings.styleCallback === 'function') {
                        return settings.styleCallback(feature, defaultStyle);
                    }
                    return defaultStyle;
                },
                filter: function(feature) {
                    // Apply filter if provided
                    if (settings.filterCallback && typeof settings.filterCallback === 'function') {
                        return settings.filterCallback(feature);
                    }
                    return true;
                },
                onEachFeature: function(feature, layer) {
                    // Store LGA ID in the layer for reference
                    if (feature.properties) {
                        layer.lgaId = feature.properties.lga_id;
                        layer.lgaName = feature.properties.lga_name;
                    }
                    
                    // Add hover effect if enabled
                    if (settings.highlightOnHover) {
                        layer.on({
                            mouseover: function(e) {
                                layer.setStyle({
                                    weight: 3,
                                    fillOpacity: 0.3
                                });
                                if (!L.Browser.ie && !L.Browser.opera && !L.Browser.edge) {
                                    layer.bringToFront();
                                }
                            },
                            mouseout: function(e) {
                                lgaLayer.resetStyle(layer);
                            }
                        });
                    }
                    
                    // Handle click events
                    layer.on('click', function(e) {
                        // Call custom click handler if provided
                        if (settings.clickHandler && typeof settings.clickHandler === 'function') {
                            settings.clickHandler(feature, layer, e);
                            return;
                        }
                        
                        // Default popup behavior
                        if (settings.showPopup) {
                            // Get LGA properties
                            const lgaName = feature.properties.lga_name;
                            const lgaId = feature.properties.lga_id;
                            const docCount = feature.properties.document_count || 0;
                            const areaSqKm = feature.properties.area_sqkm || 0;
                            
                            // Get property statistics if callback provided
                            let statsHtml = '';
                            if (settings.getPropertiesCallback && typeof settings.getPropertiesCallback === 'function') {
                                const stats = settings.getPropertiesCallback(feature, layer);
                                if (stats) {
                                    statsHtml = `
                                        <p><strong>Properties:</strong> ${stats.propertyCount || 0}</p>
                                        <p><strong>Work Records:</strong> ${stats.workCount || 0}</p>
                                        <p><strong>Total Income:</strong> $${(stats.income || 0).toLocaleString()}</p>
                                        <p><strong>Total Expenses:</strong> $${(stats.expenses || 0).toLocaleString()}</p>
                                    `;
                                }
                            }
                            
                            // Create and bind popup
                            let popupContent = `
                                <div>
                                    <h6>${lgaName}</h6>
                                    <p><strong>Area:</strong> ${Math.round(areaSqKm)} km²</p>
                                    <p><strong>Documents:</strong> ${docCount}</p>
                                    ${statsHtml}
                                </div>
                            `;
                            
                            layer.bindPopup(popupContent).openPopup();
                        }
                    });
                }
            }).addTo(map);
            
            // Store reference to current LGA layer
            window.currentLgaLayer = lgaLayer;
            
            // Return layer for further operations
            return lgaLayer;
        })
        .catch(error => {
            console.error('Error loading LGA boundaries:', error);
            return null;
        });
}

// Function to get LGA boundaries for a specific LGA ID
function getLgaBoundary(lgaId) {
    return new Promise((resolve, reject) => {
        fetch('/builders-hub?lga_geojson=true')
            .then(response => {
                if (!response.ok) {
                    throw new Error('Network response was not ok');
                }
                return response.json();
            })
            .then(lgaData => {
                const feature = lgaData.features.find(f => f.properties.lga_id === lgaId);
                if (feature) {
                    resolve(feature);
                } else {
                    reject(new Error(`LGA with ID ${lgaId} not found`));
                }
            })
            .catch(error => {
                reject(error);
            });
    });
}

// Function to check if a point is inside a LGA boundary
function isPointInLga(lat, lng, lgaId) {
    return new Promise((resolve, reject) => {
        getLgaBoundary(lgaId)
            .then(feature => {
                const point = { type: 'Point', coordinates: [lng, lat] };
                const polygon = feature.geometry;
                
                // Use turf.js for point-in-polygon check if available
                if (window.turf) {
                    const result = window.turf.booleanPointInPolygon(point, polygon);
                    resolve(result);
                } else {
                    // Simplified approach using Leaflet
                    const layer = L.geoJSON(feature);
                    const bounds = layer.getBounds();
                    const result = bounds.contains(L.latLng(lat, lng));
                    resolve(result);
                }
            })
            .catch(error => {
                reject(error);
            });
    });
}

// Export these functions for use in other scripts
window.PropIntelMaps = {
    initLgaLayer,
    getLgaBoundary,
    isPointInLga
};