import { useEffect, useRef } from 'react'
import * as THREE from 'three'

export default function Globe3D() {
  const mountRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const el = mountRef.current!
    const W = el.clientWidth, H = el.clientHeight

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true })
    renderer.setSize(W, H)
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2))
    renderer.setClearColor(0x000000, 0)
    el.appendChild(renderer.domElement)

    const scene = new THREE.Scene()
    const camera = new THREE.PerspectiveCamera(60, W / H, 0.1, 1000)
    camera.position.set(0, 0, 3.5)

    // ── Core sphere (wireframe globe) ──────────────────────────────────────
    const sphereGeo = new THREE.SphereGeometry(1.4, 32, 24)
    const sphereMat = new THREE.MeshBasicMaterial({
      color: 0x00ff88, wireframe: true, transparent: true, opacity: 0.07,
    })
    const sphere = new THREE.Mesh(sphereGeo, sphereMat)
    scene.add(sphere)

    // ── Inner glow sphere ──────────────────────────────────────────────────
    const innerGeo = new THREE.SphereGeometry(1.38, 32, 24)
    const innerMat = new THREE.MeshBasicMaterial({
      color: 0x001a0a, transparent: true, opacity: 0.6, side: THREE.FrontSide,
    })
    scene.add(new THREE.Mesh(innerGeo, innerMat))

    // ── Orbital rings ──────────────────────────────────────────────────────
    const ringMat = new THREE.LineBasicMaterial({ color: 0x00d4ff, transparent: true, opacity: 0.25 })
    ;[1.7, 2.0, 2.3].forEach((r, i) => {
      const pts: THREE.Vector3[] = []
      for (let j = 0; j <= 128; j++) {
        const a = (j / 128) * Math.PI * 2
        pts.push(new THREE.Vector3(Math.cos(a) * r, 0, Math.sin(a) * r))
      }
      const ring = new THREE.Line(new THREE.BufferGeometry().setFromPoints(pts), ringMat.clone())
      ring.rotation.x = Math.PI / 2 + i * 0.3
      ring.rotation.z = i * 0.5
      scene.add(ring)
    })

    // ── Floating attack nodes ──────────────────────────────────────────────
    const nodeMat = new THREE.PointsMaterial({ color: 0xff2d55, size: 0.05, transparent: true, opacity: 0.9 })
    const nodePositions: number[] = []
    for (let i = 0; i < 120; i++) {
      const phi = Math.acos(2 * Math.random() - 1)
      const theta = Math.random() * Math.PI * 2
      nodePositions.push(
        1.4 * Math.sin(phi) * Math.cos(theta),
        1.4 * Math.sin(phi) * Math.sin(theta),
        1.4 * Math.cos(phi),
      )
    }
    const nodeGeo = new THREE.BufferGeometry()
    nodeGeo.setAttribute('position', new THREE.Float32BufferAttribute(nodePositions, 3))
    scene.add(new THREE.Points(nodeGeo, nodeMat))

    // ── Safe nodes (green) ─────────────────────────────────────────────────
    const safePositions: number[] = []
    for (let i = 0; i < 400; i++) {
      const phi = Math.acos(2 * Math.random() - 1)
      const theta = Math.random() * Math.PI * 2
      safePositions.push(
        1.4 * Math.sin(phi) * Math.cos(theta),
        1.4 * Math.sin(phi) * Math.sin(theta),
        1.4 * Math.cos(phi),
      )
    }
    const safeGeo = new THREE.BufferGeometry()
    safeGeo.setAttribute('position', new THREE.Float32BufferAttribute(safePositions, 3))
    scene.add(new THREE.Points(safeGeo, new THREE.PointsMaterial({ color: 0x00ff88, size: 0.02, transparent: true, opacity: 0.5 })))

    // ── Attack arc lines ───────────────────────────────────────────────────
    const arcMat = new THREE.LineBasicMaterial({ color: 0xff2d55, transparent: true, opacity: 0.4 })
    for (let i = 0; i < 8; i++) {
      const pts: THREE.Vector3[] = []
      const fromPhi = Math.acos(2 * Math.random() - 1)
      const fromTheta = Math.random() * Math.PI * 2
      const toPhi = Math.acos(2 * Math.random() - 1)
      const toTheta = Math.random() * Math.PI * 2
      const from = new THREE.Vector3(
        1.4 * Math.sin(fromPhi) * Math.cos(fromTheta),
        1.4 * Math.sin(fromPhi) * Math.sin(fromTheta),
        1.4 * Math.cos(fromPhi),
      )
      const to = new THREE.Vector3(
        1.4 * Math.sin(toPhi) * Math.cos(toTheta),
        1.4 * Math.sin(toPhi) * Math.sin(toTheta),
        1.4 * Math.cos(toPhi),
      )
      for (let t = 0; t <= 40; t++) {
        const p = t / 40
        const mid = from.clone().lerp(to, p)
        mid.normalize().multiplyScalar(1.4 + 0.3 * Math.sin(p * Math.PI))
        pts.push(mid)
      }
      scene.add(new THREE.Line(new THREE.BufferGeometry().setFromPoints(pts), arcMat))
    }

    let frame = 0
    const animate = () => {
      requestAnimationFrame(animate)
      frame++
      sphere.rotation.y += 0.003
      sphere.rotation.x += 0.0005
      nodeMat.opacity = 0.7 + 0.3 * Math.sin(frame * 0.05)
      renderer.render(scene, camera)
    }
    animate()

    const onResize = () => {
      const w = el.clientWidth, h = el.clientHeight
      renderer.setSize(w, h)
      camera.aspect = w / h
      camera.updateProjectionMatrix()
    }
    window.addEventListener('resize', onResize)
    return () => {
      window.removeEventListener('resize', onResize)
      renderer.dispose()
      el.removeChild(renderer.domElement)
    }
  }, [])

  return <div ref={mountRef} style={{ width: '100%', height: '100%' }} />
}
