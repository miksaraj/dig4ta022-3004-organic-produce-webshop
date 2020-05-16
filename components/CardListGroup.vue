<template>
	<div>
		<b-list-group v-for="item in items" :key="item.id">
			<b-list-group-item>
				<nuxt-link
					v-if="type === 'chapters'"
					:to="'/chapters/' + $route.params.id + '/' + item.id"
				>
					{{ item.header }}
				</nuxt-link>
				<nuxt-link
					v-else
					:to="{
						path: $route.path + '/' + id,
						hash: '#' + item.id
					}"
				>
					{{ item.header }}
				</nuxt-link>
			</b-list-group-item>
		</b-list-group>
	</div>
</template>

<script>
export default {
	name: 'CardListGroup',
	computed: {
		items() {
			return this.$attrs.items
		},
		type() {
			return this.$attrs.type
		},
		id() {
			return this.$attrs.id
		}
	}
}
</script>
