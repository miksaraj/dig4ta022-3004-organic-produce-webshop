<template>
	<b-card>
		<h2>
			{{ item.header }}
		</h2>
		<div>
			<h5>Arvosana: {{ item.grade }}</h5>
			<b-progress :value="item.grade" max="10" class="mb-3" />
		</div>
	</b-card>
</template>
<script>
export default {
	name: 'assignment',
	computed: {
		item() {
			return this.$attrs.item
		}
	}
}
</script>
